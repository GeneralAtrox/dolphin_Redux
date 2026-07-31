// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerController.h"

#include "Common/Event.h"
#include "Core/Core.h"
#include "Core/HW/CPU.h"
#include "Core/PowerPC/BreakPoints.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/PowerPC/JitInterface.h"
#include "Core/PowerPC/MMU.h"
#include "Core/System.h"

namespace SoAL
{
namespace
{
bool Running(Core::System& system)
{
  const Core::State state = Core::GetState(system);
  return state == Core::State::Running || state == Core::State::Paused;
}

void SetError(std::string* error, std::string message)
{
  if (error)
    *error = std::move(message);
}
}  // namespace

bool LuaDebuggerController::Pause(std::string* error)
{
  if (!Running(m_system))
  {
    SetError(error, "Dolphin core is not running");
    return false;
  }
  Core::SetState(m_system, Core::State::Paused, true, true);
  const Core::CPUThreadGuard guard(m_system);
  if (Core::GetState(m_system) != Core::State::Paused)
  {
    SetError(error, "Dolphin core did not reach paused state");
    return false;
  }
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::Resume(std::string* error)
{
  if (!Running(m_system))
  {
    SetError(error, "Dolphin core is not running");
    return false;
  }
  Core::SetState(m_system, Core::State::Running, true, true);
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::StepInstruction(std::chrono::milliseconds timeout, std::string* error)
{
  if (Core::GetState(m_system) != Core::State::Paused)
  {
    SetError(error, "Instruction stepping requires paused state");
    return false;
  }
  Common::Event completed;
  m_system.GetCPU().StepOpcode(&completed);
  if (!completed.WaitFor(timeout))
  {
    SetError(error, "Instruction step timed out");
    return false;
  }
  const Core::CPUThreadGuard guard(m_system);
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::StepFrame(std::chrono::milliseconds timeout, std::string* error)
{
  if (Core::GetState(m_system) != Core::State::Paused)
  {
    SetError(error, "Frame stepping requires paused state");
    return false;
  }
  std::unique_lock lock(m_frame_mutex);
  const u64 before = m_frame_ordinal;
  Core::DoFrameStep(m_system);
  if (!m_frame_changed.wait_for(lock, timeout, [&] { return m_frame_ordinal > before; }))
  {
    SetError(error, "Frame step timed out before deterministic frame-end notification");
    return false;
  }
  lock.unlock();
  Core::SetState(m_system, Core::State::Paused, true, true);
  const Core::CPUThreadGuard guard(m_system);
  if (Core::GetState(m_system) != Core::State::Paused)
  {
    SetError(error, "Dolphin core did not return to paused state after frame step");
    return false;
  }
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::AddBreakpoint(u32 address, std::string* error)
{
  const Core::CPUThreadGuard guard(m_system);
  auto& breakpoints = m_system.GetPowerPC().GetBreakPoints();
  breakpoints.Add(address);
  if (!breakpoints.IsAddressBreakPoint(address))
  {
    SetError(error, "Breakpoint was not installed");
    return false;
  }
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::RemoveBreakpoint(u32 address, std::string* error)
{
  const Core::CPUThreadGuard guard(m_system);
  if (!m_system.GetPowerPC().GetBreakPoints().Remove(address))
  {
    SetError(error, "Breakpoint does not exist");
    return false;
  }
  if (error)
    error->clear();
  return true;
}

void LuaDebuggerController::ClearBreakpoints()
{
  const Core::CPUThreadGuard guard(m_system);
  m_system.GetPowerPC().GetBreakPoints().Clear();
}

std::vector<u32> LuaDebuggerController::Breakpoints()
{
  const Core::CPUThreadGuard guard(m_system);
  std::vector<u32> result;
  for (const TBreakPoint& breakpoint : m_system.GetPowerPC().GetBreakPoints().GetBreakPoints())
    result.push_back(breakpoint.address);
  return result;
}

bool LuaDebuggerController::ExecuteSynchronized(const std::function<void()>& function,
                                                std::string* error)
{
  if (!function || !Running(m_system))
  {
    SetError(error, "CPU/GPU synchronization requires a running core and function");
    return false;
  }
  const Core::CPUThreadGuard guard(m_system);
  function();
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerController::RefreshMemoryObservation(std::vector<std::pair<u32, u32>> ranges,
                                                      std::string* error)
{
  if (!Running(m_system))
  {
    SetError(error, "Memory-observation refresh requires a running core");
    return false;
  }
  if (m_system.GetPowerPC().GetMode() == PowerPC::CoreMode::Interpreter)
    ranges.clear();
  m_system.GetPowerPC().GetMemChecks().SetExternalMemoryObserverRanges(std::move(ranges));
  if (error)
    error->clear();
  return true;
}

void LuaDebuggerController::NotifyFrame()
{
  {
    std::lock_guard lock(m_frame_mutex);
    ++m_frame_ordinal;
  }
  m_frame_changed.notify_all();
}

u64 LuaDebuggerController::FrameOrdinal() const
{
  std::lock_guard lock(m_frame_mutex);
  return m_frame_ordinal;
}
}  // namespace SoAL
