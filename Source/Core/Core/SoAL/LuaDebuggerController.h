// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "Common/CommonTypes.h"

namespace Core
{
class System;
}

namespace SoAL
{
// Debugger state transitions for the Lua/control-server surface. CPUThreadGuard is used for every
// state inspection or breakpoint edit, which pauses and locks CPU, DSP and FIFO in Dolphin's
// required order. NotifyFrame is called by the deterministic frame-end hook.
class LuaDebuggerController final
{
public:
  explicit LuaDebuggerController(Core::System& system) : m_system(system) {}

  bool Pause(std::string* error = nullptr);
  bool Resume(std::string* error = nullptr);
  bool StepInstruction(std::chrono::milliseconds timeout, std::string* error = nullptr);
  bool StepFrame(std::chrono::milliseconds timeout, std::string* error = nullptr);
  bool AddBreakpoint(u32 address, std::string* error = nullptr);
  bool RemoveBreakpoint(u32 address, std::string* error = nullptr);
  void ClearBreakpoints();
  std::vector<u32> Breakpoints();
  bool ExecuteSynchronized(const std::function<void()>& function,
                           std::string* error = nullptr);
  bool RefreshMemoryObservation(std::vector<std::pair<u32, u32>> ranges,
                                std::string* error = nullptr);

  void NotifyFrame();
  u64 FrameOrdinal() const;

private:
  Core::System& m_system;
  mutable std::mutex m_frame_mutex;
  std::condition_variable m_frame_changed;
  u64 m_frame_ordinal = 0;
};
}  // namespace SoAL
