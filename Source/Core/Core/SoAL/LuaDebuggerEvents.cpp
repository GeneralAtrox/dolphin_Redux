// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerEvents.h"

#include <algorithm>
#include <utility>

namespace SoAL
{
namespace
{
bool ValidFunctionName(std::string_view name)
{
  if (name.empty() || name.size() > 255)
    return false;
  return std::ranges::all_of(name, [](unsigned char byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '_' || byte == '.';
  });
}
}  // namespace

LuaDebuggerEventQueue::LuaDebuggerEventQueue(Dispatch dispatch) : m_dispatch(std::move(dispatch))
{
}

LuaDebuggerEventQueue::~LuaDebuggerEventQueue()
{
  Stop();
}

bool LuaDebuggerEventQueue::Start(std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (m_started || !m_dispatch)
  {
    if (error)
      *error = m_started ? "Lua debugger event queue is already started" :
                           "Lua debugger event queue has no dispatcher";
    return false;
  }
  m_stopping = false;
  m_started = true;
  m_thread = std::thread(&LuaDebuggerEventQueue::ThreadMain, this);
  if (error)
    error->clear();
  return true;
}

void LuaDebuggerEventQueue::Stop()
{
  {
    std::lock_guard lock(m_mutex);
    if (!m_started)
      return;
    m_stopping = true;
  }
  m_ready.notify_one();
  if (m_thread.joinable())
    m_thread.join();
  std::lock_guard lock(m_mutex);
  m_started = false;
  m_stopping = false;
  m_script_thread_id = {};
  m_events.clear();
  m_queued_payload_bytes = 0;
  m_tasks.clear();
  m_dispatching = false;
}

bool LuaDebuggerEventQueue::Register(LuaDebuggerEventKind kind,
                                     std::optional<LuaDebuggerAddressFilter> address_filter,
                                     std::string lua_function, u64* id, std::string* error)
{
  if (!ValidFunctionName(lua_function) || (address_filter && !HasAddress(kind)) ||
      (address_filter && address_filter->first > address_filter->last))
  {
    if (error)
      *error = "Lua debugger callback name or address filter is invalid";
    return false;
  }
  std::lock_guard lock(m_mutex);
  if (m_next_registration_id == 0)
  {
    if (error)
      *error = "Lua debugger callback identifier space exhausted";
    return false;
  }
  const u64 assigned = m_next_registration_id++;
  m_registrations.push_back({assigned, kind, address_filter, std::move(lua_function)});
  if (id)
    *id = assigned;
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerEventQueue::Unregister(u64 id)
{
  std::lock_guard lock(m_mutex);
  const auto it = std::ranges::find(m_registrations, id,
                                    &LuaDebuggerCallbackRegistration::id);
  if (it == m_registrations.end())
    return false;
  m_registrations.erase(it);
  return true;
}

bool LuaDebuggerEventQueue::Enqueue(LuaDebuggerEvent event, std::string* error)
{
  std::lock_guard lock(m_mutex);
  const bool backwards = m_have_enqueue_key && event.source_ordinal <= m_last_enqueued_ordinal;
  const bool invalid_gx_payload =
      ((event.kind == LuaDebuggerEventKind::GXCommand ||
        event.kind == LuaDebuggerEventKind::GXDraw) &&
       (event.gx_payload.size() != event.size ||
        event.gx_payload.size() > LuaDebuggerEvent::MAX_GX_PAYLOAD_BYTES)) ||
      event.gx_state_payload.size() > LuaDebuggerEvent::MAX_GX_PAYLOAD_BYTES ||
      event.effective_pipeline_definition.size() > LuaDebuggerEvent::MAX_GX_PAYLOAD_BYTES ||
      event.effective_pipeline_bindings.size() > LuaDebuggerEvent::MAX_GX_PAYLOAD_BYTES;
  constexpr size_t MAX_QUEUED_PAYLOAD_BYTES = 256 * 1024 * 1024;
  const size_t payload_bytes = event.gx_payload.size() + event.gx_state_payload.size() +
                               event.effective_pipeline_definition.size() +
                               event.effective_pipeline_bindings.size();
  const bool payload_capacity_exhausted =
      payload_bytes > MAX_QUEUED_PAYLOAD_BYTES - m_queued_payload_bytes;
  if (!m_started || m_stopping || backwards || invalid_gx_payload ||
      m_events.size() >= 1'000'000 || payload_capacity_exhausted)
  {
    if (error)
      *error = !m_started ? "Lua debugger event queue is not running" :
               m_stopping ? "Lua debugger event queue is stopping" :
               backwards ? "Lua debugger event key is not strictly increasing" :
               invalid_gx_payload ? "Lua debugger GX payload is incomplete or exceeds its bound" :
               payload_capacity_exhausted ? "Lua debugger GX payload queue capacity exhausted" :
                           "Lua debugger event queue capacity exhausted";
    return false;
  }
  m_last_enqueued_ordinal = event.source_ordinal;
  m_have_enqueue_key = true;
  m_queued_payload_bytes += payload_bytes;
  m_events.push_back(std::move(event));
  m_ready.notify_one();
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerEventQueue::ExecuteSync(std::function<void()> task, std::string* error)
{
  if (!task)
  {
    if (error)
      *error = "Lua debugger synchronous task is empty";
    return false;
  }
  if (IsScriptThread())
  {
    task();
    if (error)
      error->clear();
    return true;
  }
  auto queued = std::make_shared<SyncTask>();
  queued->function = std::move(task);
  std::future<void> completion = queued->completion.get_future();
  {
    std::lock_guard lock(m_mutex);
    if (!m_started || m_stopping || m_dispatching || !m_events.empty() || !m_tasks.empty())
    {
      if (error)
        *error = "Lua debugger synchronous task requires an idle running script thread";
      return false;
    }
    m_tasks.push_back(queued);
  }
  m_ready.notify_one();
  completion.get();
  if (error)
    error->clear();
  return true;
}

void LuaDebuggerEventQueue::WaitUntilIdle()
{
  std::unique_lock lock(m_mutex);
  m_idle.wait(lock, [this] { return m_events.empty() && !m_dispatching; });
}

bool LuaDebuggerEventQueue::IsScriptThread() const
{
  std::lock_guard lock(m_mutex);
  return std::this_thread::get_id() == m_script_thread_id;
}

size_t LuaDebuggerEventQueue::PendingCount() const
{
  std::lock_guard lock(m_mutex);
  return m_events.size() + (m_dispatching ? 1 : 0);
}

std::vector<LuaDebuggerCallbackRegistration> LuaDebuggerEventQueue::Registrations() const
{
  std::lock_guard lock(m_mutex);
  return m_registrations;
}

bool LuaDebuggerEventQueue::HasMatchingRegistration(LuaDebuggerEventKind kind, u32 address) const
{
  std::lock_guard lock(m_mutex);
  return std::ranges::any_of(m_registrations, [&](const auto& registration) {
    return registration.kind == kind &&
           (!registration.address_filter || registration.address_filter->Contains(address));
  });
}

bool LuaDebuggerEventQueue::HasRegistrationKind(LuaDebuggerEventKind kind) const
{
  std::lock_guard lock(m_mutex);
  return std::ranges::any_of(m_registrations,
                             [kind](const auto& registration) { return registration.kind == kind; });
}

bool LuaDebuggerEventQueue::HasAddress(LuaDebuggerEventKind kind)
{
  return kind == LuaDebuggerEventKind::Instruction || kind == LuaDebuggerEventKind::MemoryRead ||
         kind == LuaDebuggerEventKind::MemoryWrite || kind == LuaDebuggerEventKind::GXCommand;
}

void LuaDebuggerEventQueue::ThreadMain()
{
  {
    std::lock_guard lock(m_mutex);
    m_script_thread_id = std::this_thread::get_id();
  }
  for (;;)
  {
    LuaDebuggerEvent event;
    std::vector<LuaDebuggerCallbackRegistration> registrations;
    {
      std::unique_lock lock(m_mutex);
      m_ready.wait(lock, [this] { return m_stopping || !m_tasks.empty() || !m_events.empty(); });
      if (m_stopping && m_tasks.empty() && m_events.empty())
        break;
      if (!m_tasks.empty())
      {
        const std::shared_ptr<SyncTask> task = m_tasks.front();
        m_tasks.pop_front();
        m_dispatching = true;
        lock.unlock();
        try
        {
          task->function();
          task->completion.set_value();
        }
        catch (...)
        {
          task->completion.set_exception(std::current_exception());
        }
        lock.lock();
        m_dispatching = false;
        m_idle.notify_all();
        continue;
      }
      event = std::move(m_events.front());
      m_queued_payload_bytes -= event.gx_payload.size() + event.gx_state_payload.size() +
                                event.effective_pipeline_definition.size() +
                                event.effective_pipeline_bindings.size();
      m_events.pop_front();
      registrations = m_registrations;
      m_dispatching = true;
    }
    for (const LuaDebuggerCallbackRegistration& registration : registrations)
    {
      if (registration.kind != event.kind)
        continue;
      if (registration.address_filter && !registration.address_filter->Contains(event.address))
        continue;
      m_dispatch(registration, event);
    }
    {
      std::lock_guard lock(m_mutex);
      m_dispatching = false;
      if (m_events.empty())
        m_idle.notify_all();
    }
  }
  std::lock_guard lock(m_mutex);
  m_dispatching = false;
  m_idle.notify_all();
}
}  // namespace SoAL
