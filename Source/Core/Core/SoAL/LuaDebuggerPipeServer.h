// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <atomic>
#include <string>
#include <thread>

namespace SoAL
{
class LuaDebuggerPipeServer final
{
public:
  static LuaDebuggerPipeServer& Get();

  void Start();
  void Stop();

private:
  LuaDebuggerPipeServer() = default;
  ~LuaDebuggerPipeServer();
  LuaDebuggerPipeServer(const LuaDebuggerPipeServer&) = delete;
  LuaDebuggerPipeServer& operator=(const LuaDebuggerPipeServer&) = delete;

  void Run();
  std::string HandleCommand(const std::string& command);

  std::atomic<bool> m_running = false;
  std::string m_pipe_name = "dolphin-redux";
  std::thread m_thread;
};
}  // namespace SoAL
