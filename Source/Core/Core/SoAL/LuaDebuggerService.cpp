// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerService.h"

#include <charconv>
#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

#include <fmt/format.h>

#include "Common/SymbolDB.h"
#include "Core/Core.h"
#include "Core/CoreTiming.h"
#include "Core/HW/Memmap.h"
#include "Core/PowerPC/Gekko.h"
#include "Core/PowerPC/MMU.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/PowerPC/PPCSymbolDB.h"
#include "Core/System.h"
#include "Core/SoAL/LuaDebuggerController.h"
#include "Core/SoAL/LuaDebuggerRuntime.h"
#include "Core/SoAL/LuaDebuggerSession.h"
#include "Core/SoAL/LuaDebuggerSha256.h"

namespace SoAL
{
LuaDebuggerService& LuaDebuggerService::Get()
{
  static LuaDebuggerService service;
  return service;
}

bool LuaDebuggerService::Start(Core::System& system, std::string runtime_library,
                               std::span<const u8> script, std::string canonical_name,
                               std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  if (m_runtime)
  {
    if (error)
      *error = "Lua debugger service is already active";
    return false;
  }
  m_system = &system;
  m_session = std::make_unique<LuaDebuggerSession>();
  m_controller = std::make_unique<LuaDebuggerController>(system);
  LuaDebuggerReadProviders providers;
  providers.memory = [this](u32 address, u32 size, std::vector<u8>* bytes) {
    bool read = false;
    if (!m_controller || !m_system)
      return false;
    m_controller->ExecuteSynchronized([&] {
      if (size == 0 || static_cast<u64>(address) + size >
                           static_cast<u64>(std::numeric_limits<u32>::max()) + 1)
        return;
      const u8* pointer = m_system->GetMemory().GetPointerForRange(address, size);
      if (!pointer)
        return;
      bytes->assign(pointer, pointer + size);
      read = true;
    });
    return read;
  };
  providers.reg = [this](std::string_view name, u64* value) {
    bool read = false;
    if (!m_controller || !m_system)
      return false;
    m_controller->ExecuteSynchronized([&] {
      const PowerPC::PowerPCState& state = m_system->GetPPCState();
      if (name.size() >= 2 && name.front() == 'r')
      {
        u32 index = 0;
        const auto result = std::from_chars(name.data() + 1, name.data() + name.size(), index);
        if (result.ec == std::errc{} && result.ptr == name.data() + name.size() && index < 32)
        {
          *value = state.gpr[index];
          read = true;
        }
      }
      else if (name == "pc")
        *value = state.pc, read = true;
      else if (name == "npc")
        *value = state.npc, read = true;
      else if (name == "lr")
        *value = LR(state), read = true;
      else if (name == "ctr")
        *value = CTR(state), read = true;
      else if (name == "cr")
        *value = state.cr.Get(), read = true;
      else if (name == "xer")
        *value = state.GetXER().Hex, read = true;
      else if (name == "msr")
        *value = state.msr.Hex, read = true;
      else if (name == "fpscr")
        *value = state.fpscr.Hex, read = true;
    });
    return read;
  };
  providers.symbol = [this](std::string_view name, u32* address) {
    bool found = false;
    if (!m_controller || !m_system)
      return false;
    m_controller->ExecuteSynchronized([&] {
      const Common::Symbol* symbol = m_system->GetPPCSymbolDB().GetSymbolFromName(name);
      if (symbol)
      {
        *address = symbol->address;
        found = true;
      }
    });
    return found;
  };
  providers.write_memory = [this](u32 address, std::span<const u8> bytes) {
    bool written = false;
    if (!m_controller || !m_system || bytes.empty())
      return false;
    m_controller->ExecuteSynchronized([&] {
      u8* pointer = m_system->GetMemory().GetPointerForRange(address, bytes.size());
      if (!pointer)
        return;
      std::ranges::copy(bytes, pointer);
      written = true;
    });
    return written;
  };
  providers.write_reg = [this](std::string_view name, u64 value) {
    bool written = false;
    if (!m_controller || !m_system || value > UINT32_MAX)
      return false;
    m_controller->ExecuteSynchronized([&] {
      PowerPC::PowerPCState& state = m_system->GetPPCState();
      if (name.size() >= 2 && name.front() == 'r')
      {
        u32 index = 0;
        const auto result = std::from_chars(name.data() + 1, name.data() + name.size(), index);
        if (result.ec == std::errc{} && result.ptr == name.data() + name.size() && index < 32)
          state.gpr[index] = static_cast<u32>(value), written = true;
      }
      else if (name == "pc")
        state.pc = static_cast<u32>(value), written = true;
      else if (name == "npc")
        state.npc = static_cast<u32>(value), written = true;
      else if (name == "lr")
        LR(state) = static_cast<u32>(value), written = true;
      else if (name == "ctr")
        CTR(state) = static_cast<u32>(value), written = true;
      else if (name == "cr")
        state.cr.Set(static_cast<u32>(value)), written = true;
    });
    return written;
  };
  m_runtime = std::make_unique<LuaDebuggerRuntime>(*m_session, std::move(providers));
  if (!m_runtime->Load(std::move(runtime_library), script, std::move(canonical_name), error))
  {
    m_runtime.reset();
    m_controller.reset();
    m_session.reset();
    m_system = nullptr;
    return false;
  }
  m_source_ordinal = 0;
  m_video_frame_ordinal.store(0, std::memory_order_relaxed);
  m_gx_command_ordinal.store(0, std::memory_order_relaxed);
  m_gx_draw_ordinal.store(0, std::memory_order_relaxed);
  m_gx_frame_draw_ordinal.store(0, std::memory_order_relaxed);
  m_effective_pipeline_definitions.clear();
  m_hook_errors.clear();
  m_hook_failure_latched = false;
  m_active.store(true, std::memory_order_release);
  lock.unlock();
  m_controller->ExecuteSynchronized([&] {
    if (m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::Instruction) &&
        system.GetPowerPC().GetMode() != PowerPC::CoreMode::Interpreter)
    {
      system.GetPowerPC().SetMode(PowerPC::CoreMode::Interpreter);
      m_forced_interpreter = true;
    }
  });
  m_controller->RefreshMemoryObservation(MemoryObserverRanges());
  return true;
}

void LuaDebuggerService::Stop()
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_ptr<LuaDebuggerRuntime> runtime;
  {
    std::unique_lock lock(m_mutex);
    m_active.store(false, std::memory_order_release);
    LuaDebuggerController* const controller = m_controller.get();
    Core::System* const system = m_system;
    const bool restore_jit = m_forced_interpreter;
    m_forced_interpreter = false;
    lock.unlock();
    if (controller && system)
    {
      controller->ExecuteSynchronized([&] {
        if (restore_jit)
          system->GetPowerPC().SetMode(PowerPC::CoreMode::JIT);
      });
      controller->RefreshMemoryObservation({});
    }
    lock.lock();
    runtime = std::move(m_runtime);
    m_controller.reset();
    m_session.reset();
    m_system = nullptr;
  }
  if (runtime)
    runtime->Stop();
}

bool LuaDebuggerService::IsActive() const
{
  return m_active.load(std::memory_order_acquire);
}

bool LuaDebuggerService::WantsMemoryHooks() const
{
  if (!IsActive())
    return false;
  std::unique_lock lock(m_mutex);
  return m_runtime &&
         (m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::MemoryRead) ||
          m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::MemoryWrite));
}

std::vector<std::pair<u32, u32>> LuaDebuggerService::MemoryObserverRanges() const
{
  std::lock_guard lock(m_mutex);
  std::vector<std::pair<u32, u32>> ranges;
  if (!m_runtime || !IsActive())
    return ranges;
  for (const LuaDebuggerCallbackRegistration& registration : m_runtime->Events().Registrations())
  {
    if ((registration.kind == LuaDebuggerEventKind::MemoryRead ||
         registration.kind == LuaDebuggerEventKind::MemoryWrite) &&
        registration.address_filter)
    {
      ranges.emplace_back(registration.address_filter->first, registration.address_filter->last);
    }
  }
  std::ranges::sort(ranges);
  ranges.erase(std::unique(ranges.begin(), ranges.end()), ranges.end());
  return ranges;
}

bool LuaDebuggerService::WantsInstructionAt(u32 address) const
{
  if (!IsActive())
    return false;
  std::lock_guard lock(m_mutex);
  return m_runtime &&
         m_runtime->Events().HasMatchingRegistration(LuaDebuggerEventKind::Instruction, address);
}

bool LuaDebuggerService::WantsPresentObservation() const
{
  if (!IsActive())
    return false;
  std::lock_guard lock(m_mutex);
  return m_runtime &&
         m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::Present);
}

bool LuaDebuggerService::WantsEffectivePipelineObservation() const
{
  if (!IsActive())
    return false;
  std::lock_guard lock(m_mutex);
  return m_runtime &&
         m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::EffectivePipeline);
}

u64 LuaDebuggerService::LatestGXDrawOrdinal() const
{
  return m_gx_draw_ordinal.load(std::memory_order_relaxed);
}

bool LuaDebuggerService::Reload(std::span<const u8> script, std::string canonical_name,
                                std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerRuntime* const runtime = m_runtime.get();
  LuaDebuggerController* const controller = m_controller.get();
  Core::System* const system = m_system;
  const bool recovering_from_hook_failure = m_hook_failure_latched;
  if (!runtime || !controller || !system)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  lock.unlock();
  m_active.store(false, std::memory_order_release);
  const bool reloaded = runtime->Reload(script, std::move(canonical_name), error);
  if (!reloaded)
  {
    m_active.store(!recovering_from_hook_failure, std::memory_order_release);
    return false;
  }
  lock.lock();
  m_hook_failure_latched = false;
  lock.unlock();
  m_active.store(true, std::memory_order_release);
  lock.lock();
  const bool has_instruction_callbacks =
      runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::Instruction);
  const bool force_interpreter = !m_forced_interpreter && has_instruction_callbacks;
  const bool restore_jit = m_forced_interpreter && !has_instruction_callbacks;
  lock.unlock();
  if (force_interpreter || restore_jit)
  {
    controller->ExecuteSynchronized([&] {
      if (force_interpreter &&
          system->GetPowerPC().GetMode() != PowerPC::CoreMode::Interpreter)
      {
        system->GetPowerPC().SetMode(PowerPC::CoreMode::Interpreter);
        std::lock_guard state_lock(m_mutex);
        m_forced_interpreter = true;
      }
      else if (restore_jit)
      {
        system->GetPowerPC().SetMode(PowerPC::CoreMode::JIT);
        std::lock_guard state_lock(m_mutex);
        m_forced_interpreter = false;
      }
    });
  }
  controller->RefreshMemoryObservation(MemoryObserverRanges());
  return true;
}

bool LuaDebuggerService::Console(std::span<const u8> command, std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerRuntime* const runtime = m_runtime.get();
  lock.unlock();
  if (!runtime)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return runtime->EvaluateConsole(command, error);
}

bool LuaDebuggerService::EnableMutation(std::string reason, std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::lock_guard lock(m_mutex);
  if (!m_session)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return m_session->EnableMutation(std::move(reason), error);
}

std::string LuaDebuggerService::StatusJson() const
{
  std::lock_guard lock(m_mutex);
  return m_session ? m_session->StatusToJson() :
                     "{\"schema\":\"soal.lua-debugger-session.v1\",\"loaded\":false}";
}

std::vector<std::string> LuaDebuggerService::TakeOutput()
{
  std::lock_guard lock(m_mutex);
  return m_runtime ? m_runtime->TakeOutput() : std::vector<std::string>{};
}

std::vector<std::string> LuaDebuggerService::TakeErrors()
{
  std::lock_guard lock(m_mutex);
  std::vector<std::string> errors = std::exchange(m_hook_errors, {});
  if (m_runtime)
  {
    std::vector<std::string> runtime_errors = m_runtime->TakeErrors();
    errors.insert(errors.end(), std::make_move_iterator(runtime_errors.begin()),
                  std::make_move_iterator(runtime_errors.end()));
  }
  return errors;
}

bool LuaDebuggerService::Pause(std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  if (!controller)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return controller->Pause(error);
}
bool LuaDebuggerService::Resume(std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  if (!controller)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return controller->Resume(error);
}
bool LuaDebuggerService::StepInstruction(std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  if (!m_controller || !m_runtime)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  LuaDebuggerController* const controller = m_controller.get();
  LuaDebuggerRuntime* const runtime = m_runtime.get();
  lock.unlock();
  if (!controller->StepInstruction(std::chrono::seconds(15), error))
    return false;
  runtime->WaitUntilIdle();
  return true;
}
bool LuaDebuggerService::StepFrame(std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  if (!m_controller || !m_runtime)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  LuaDebuggerController* const controller = m_controller.get();
  LuaDebuggerRuntime* const runtime = m_runtime.get();
  lock.unlock();
  if (!controller->StepFrame(std::chrono::seconds(15), error))
    return false;
  runtime->WaitUntilIdle();
  return true;
}
bool LuaDebuggerService::AddBreakpoint(u32 address, std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  if (!controller)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return controller->AddBreakpoint(address, error);
}
bool LuaDebuggerService::RemoveBreakpoint(u32 address, std::string* error)
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  if (!controller)
  {
    if (error)
      *error = "Lua debugger is not active";
    return false;
  }
  return controller->RemoveBreakpoint(address, error);
}

void LuaDebuggerService::ClearBreakpoints()
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  if (controller)
    controller->ClearBreakpoints();
}

std::vector<u32> LuaDebuggerService::Breakpoints()
{
  std::lock_guard operation_lock(m_operation_mutex);
  std::unique_lock lock(m_mutex);
  LuaDebuggerController* const controller = m_controller.get();
  lock.unlock();
  return controller ? controller->Breakpoints() : std::vector<u32>{};
}

bool LuaDebuggerService::Enqueue(Core::System& system, LuaDebuggerEvent event)
{
  if (!IsActive())
    return false;
  std::lock_guard lock(m_mutex);
  if (!m_runtime || m_system != &system)
    return false;
  event.emulated_ticks = system.GetCoreTiming().GetTicks();
  event.source_ordinal = ++m_source_ordinal;
  std::string error;
  if (!m_runtime->Enqueue(std::move(event), &error))
  {
    if (!m_hook_failure_latched)
    {
      m_hook_failure_latched = true;
      m_active.store(false, std::memory_order_release);
      m_session->RecordRuntimeFailure(error);
      m_hook_errors.push_back(std::move(error));
    }
    return false;
  }
  return true;
}

void LuaDebuggerService::ObserveInstruction(Core::System& system, u32 address)
{
  if (!IsActive())
    return;
  if (WantsInstructionAt(address))
    Enqueue(system, {.kind = LuaDebuggerEventKind::Instruction,
                     .address = address,
                     .pc = address,
                     .link_register = LR(system.GetPPCState())});
}

void LuaDebuggerService::ObserveMemory(Core::System& system, u32 address, u64 value, u32 size,
                                       u32 pc, u32 link_register, bool write)
{
  if (!IsActive())
    return;
  const LuaDebuggerEventKind kind =
      write ? LuaDebuggerEventKind::MemoryWrite : LuaDebuggerEventKind::MemoryRead;
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime || !m_runtime->Events().HasMatchingRegistration(kind, address))
      return;
  }
  Enqueue(system,
          {.kind = kind,
           .address = address,
           .value = value,
           .size = size,
           .auxiliary = pc,
           .pc = pc,
           .link_register = link_register});
}

void LuaDebuggerService::ObserveFrame(Core::System& system)
{
  if (!IsActive())
    return;
  const u64 frame_ordinal = m_video_frame_ordinal.fetch_add(1, std::memory_order_relaxed) + 1;
  m_gx_frame_draw_ordinal.store(0, std::memory_order_relaxed);
  bool wants_callback = false;
  {
    std::lock_guard lock(m_mutex);
    if (m_controller)
      m_controller->NotifyFrame();
    wants_callback = m_runtime &&
                     m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::Frame);
  }
  if (wants_callback)
  {
    LuaDebuggerEvent event{.kind = LuaDebuggerEventKind::Frame,
                           .video_frame_ordinal = frame_ordinal};
    CapturePresentationSnapshot(system, &event);
    Enqueue(system, std::move(event));
  }
}

void LuaDebuggerService::ObservePresent(Core::System& system, u64 present_ordinal, u64 frame_number,
                                        u32 xfb_address, u32 xfb_width, u32 xfb_stride,
                                        u32 xfb_height, u64 resource_id, u64 resource_hash,
                                        u64 resource_base_hash, u32 resource_content_ordinal,
                                        bool duplicate_xfb, std::string render_source,
                                        bool pixel_hash_valid, std::array<u8, 32> pixel_sha256,
                                        u32 pixel_width, u32 pixel_height, u32 pixel_stride,
                                        u32 pixel_format)
{
  if (!IsActive())
    return;
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime ||
        !m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::Present))
      return;
  }
  LuaDebuggerEvent event{.kind = LuaDebuggerEventKind::Present,
                         .value = present_ordinal,
                         .video_frame_ordinal =
                             m_video_frame_ordinal.load(std::memory_order_relaxed),
                         .render_resource_id = resource_id,
                         .render_resource_hash = resource_hash,
                         .render_resource_base_hash = resource_base_hash,
                         .render_resource_content_ordinal = resource_content_ordinal,
                         .xfb_address = xfb_address,
                         .xfb_stride = xfb_stride,
                         .xfb_width = xfb_width,
                         .xfb_height = xfb_height,
                         .render_flags = duplicate_xfb ? 1u : 0u,
                         .presented_frame_number = frame_number,
                         .present_pixel_hash_valid = pixel_hash_valid,
                         .present_pixel_sha256 = pixel_sha256,
                         .present_pixel_width = pixel_width,
                         .present_pixel_height = pixel_height,
                         .present_pixel_stride = pixel_stride,
                         .present_pixel_format = pixel_format,
                         .render_source = std::move(render_source)};
  CapturePresentationSnapshot(system, &event);
  Enqueue(system, std::move(event));
}

u64 LuaDebuggerService::ObserveGXCommand(Core::System& system, std::span<const u8> command)
{
  if (!IsActive() || command.empty())
    return 0;
  const u64 command_ordinal =
      m_gx_command_ordinal.fetch_add(1, std::memory_order_relaxed) + 1;
  const u32 opcode = command.front();
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime || !m_runtime->Events().HasMatchingRegistration(
                          LuaDebuggerEventKind::GXCommand, opcode))
      return command_ordinal;
  }
  const u32 prefix_size = static_cast<u32>(std::min<size_t>(command.size(), sizeof(u64)));
  u64 prefix = 0;
  for (u32 index = 0; index < prefix_size; ++index)
    prefix = (prefix << 8) | command[index];
  LuaDebuggerEvent event{.kind = LuaDebuggerEventKind::GXCommand,
                         .address = opcode,
                         .value = opcode,
                         .size = static_cast<u32>(command.size()),
                         .gx_prefix = prefix,
                         .gx_prefix_size = prefix_size,
                         .video_frame_ordinal =
                             m_video_frame_ordinal.load(std::memory_order_relaxed) + 1,
                         .gx_command_ordinal = command_ordinal};
  if (command.size() <= LuaDebuggerEvent::MAX_GX_PAYLOAD_BYTES)
    event.gx_payload.assign(command.begin(), command.end());
  CapturePresentationSnapshot(system, &event);
  Enqueue(system, std::move(event));
  return command_ordinal;
}

void LuaDebuggerService::ObserveGXDraw(Core::System& system, u64 gx_command_ordinal,
                                       std::span<const u8> command, u32 primitive, u32 vat,
                                       u32 vertex_size, u32 vertex_count,
                                       std::span<const u8> gx_state_payload)
{
  if (!IsActive() || gx_command_ordinal == 0 || command.empty())
    return;
  bool emit_draw = false;
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime)
      return;
    emit_draw = m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::GXDraw);
    if (!emit_draw &&
        !m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::EffectivePipeline))
      return;
  }
  const u64 draw_ordinal = m_gx_draw_ordinal.fetch_add(1, std::memory_order_relaxed) + 1;
  const u64 frame_draw_ordinal =
      m_gx_frame_draw_ordinal.fetch_add(1, std::memory_order_relaxed) + 1;
  if (!emit_draw)
    return;
  LuaDebuggerEvent event{
      .kind = LuaDebuggerEventKind::GXDraw,
      .address = command.front(),
      .value = command.front(),
      .size = static_cast<u32>(command.size()),
      .video_frame_ordinal = m_video_frame_ordinal.load(std::memory_order_relaxed) + 1,
      .gx_command_ordinal = gx_command_ordinal,
      .gx_draw_ordinal = draw_ordinal,
      .gx_frame_draw_ordinal = frame_draw_ordinal,
      .gx_primitive = primitive,
      .gx_vat = vat,
      .gx_vertex_size = vertex_size,
      .gx_vertex_count = vertex_count,
  };
  event.gx_payload.assign(command.begin(), command.end());
  event.gx_state_payload.assign(gx_state_payload.begin(), gx_state_payload.end());
  event.gx_state_sha256 = Sha256(event.gx_state_payload);
  CapturePresentationSnapshot(system, &event);
  Enqueue(system, std::move(event));
}

void LuaDebuggerService::ObserveEFBCopy(Core::System& system,
                                        const LuaDebuggerEfbCopyInfo& info)
{
  if (!IsActive())
    return;
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime || !m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::EFBCopy))
      return;
  }
  LuaDebuggerEvent event{
      .kind = LuaDebuggerEventKind::EFBCopy,
      .video_frame_ordinal = m_video_frame_ordinal.load(std::memory_order_relaxed) + 1,
      .render_resource_id = info.resource_id,
      .render_resource_hash = info.resource_hash,
      .render_resource_base_hash = info.resource_base_hash,
      .render_resource_content_ordinal = info.resource_content_ordinal,
      .xfb_address = info.destination_address,
      .xfb_stride = info.destination_stride,
      .xfb_width = info.copy_width,
      .xfb_height = info.copy_height,
      .efb_left = info.source_left,
      .efb_top = info.source_top,
      .efb_right = info.source_right,
      .efb_bottom = info.source_bottom,
      .copy_filter_coefficients = info.vram_filter_coefficients,
      .copy_gamma_bits = info.gamma_bits,
      .copy_y_scale_bits = info.y_scale_bits,
      .copy_parameter_flags = info.copy_parameter_flags,
      .render_flags = (info.copy_to_vram ? 1u : 0u) | (info.copy_to_ram ? 2u : 0u) |
                      (info.copy_to_xfb ? 4u : 0u) | (info.depth_copy ? 8u : 0u),
      .raw_pixel_capture_valid = info.raw_pixel_capture_valid,
      .efb_source_pixels_sha256 = info.efb_source_pixels_sha256,
      .xfb_copy_pixels_sha256 = info.xfb_copy_pixels_sha256,
      .captured_pixel_width = info.captured_pixel_width,
      .captured_pixel_height = info.captured_pixel_height,
      .captured_pixel_stride = info.captured_pixel_stride,
      .captured_pixel_format = info.captured_pixel_format,
  };
  CapturePresentationSnapshot(system, &event);
  Enqueue(system, std::move(event));
}

void LuaDebuggerService::ObserveEffectivePipeline(Core::System& system,
                                                   LuaDebuggerEffectivePipelineInfo info)
{
  if (!IsActive() || info.gx_draw_ordinal == 0 || info.definition.empty() ||
      info.bindings.empty())
    return;
  {
    std::lock_guard lock(m_mutex);
    if (!m_runtime ||
        !m_runtime->Events().HasRegistrationKind(LuaDebuggerEventKind::EffectivePipeline))
      return;
  }

  const std::array<u8, 32> definition_sha256 = Sha256(info.definition);
  const std::array<u8, 32> bindings_sha256 = Sha256(info.bindings);
  {
    std::lock_guard lock(m_mutex);
    const auto [unused, inserted] = m_effective_pipeline_definitions.insert(definition_sha256);
    if (!inserted)
      info.definition.clear();
  }
  LuaDebuggerEvent event{
      .kind = LuaDebuggerEventKind::EffectivePipeline,
      .effective_pipeline_definition = std::move(info.definition),
      .effective_pipeline_definition_sha256 = definition_sha256,
      .effective_pipeline_bindings = std::move(info.bindings),
      .effective_pipeline_bindings_sha256 = bindings_sha256,
      .effective_draw_kind = info.draw_kind,
      .effective_draw_base = info.draw_base,
      .effective_draw_count = info.draw_count,
      .effective_base_vertex = info.base_vertex,
      .video_frame_ordinal = m_video_frame_ordinal.load(std::memory_order_relaxed) + 1,
      .gx_draw_ordinal = info.gx_draw_ordinal,
  };
  CapturePresentationSnapshot(system, &event);
  Enqueue(system, std::move(event));
}

void LuaDebuggerService::CapturePresentationSnapshot(Core::System& system,
                                                      LuaDebuggerEvent* event)
{
  if (!event)
    return;
  auto& memory = system.GetMemory();
  constexpr u32 TITLE_STATE = 0x80311ae0;
  constexpr std::array<u32, 6> FADE_ADDRESSES = {
      0x80347504, 0x80347508, 0x8034750c, 0x80347510, 0x80347514, 0x80347518,
  };
  if (!memory.GetPointerForRange(TITLE_STATE, sizeof(u32)))
    return;
  for (const u32 address : FADE_ADDRESSES)
  {
    if (!memory.GetPointerForRange(address, sizeof(u32)))
      return;
  }
  event->title_state = memory.Read_U32(TITLE_STATE);
  for (size_t index = 0; index < FADE_ADDRESSES.size(); ++index)
    event->fade_words[index] = memory.Read_U32(FADE_ADDRESSES[index]);
  event->presentation_snapshot_valid = true;
}
}  // namespace SoAL
