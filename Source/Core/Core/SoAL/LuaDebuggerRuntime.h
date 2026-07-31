// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "Common/CommonTypes.h"
#include "Core/SoAL/LuaDebuggerEvents.h"
#include "Core/SoAL/LuaDebuggerSession.h"

namespace SoAL
{
struct LuaDebuggerReadProviders
{
  std::function<bool(u32 address, u32 size, std::vector<u8>* bytes)> memory;
  std::function<bool(std::string_view name, u64* value)> reg;
  std::function<bool(std::string_view name, u32* address)> symbol;
  std::function<bool(u32 address, std::span<const u8> bytes)> write_memory;
  std::function<bool(std::string_view name, u64 value)> write_reg;
};

struct LuaDebuggerRuntimeLimits
{
  size_t memory_bytes = 16 * 1024 * 1024;
  u64 instructions_per_call = 1'000'000;
  size_t output_records = 1'000'000;
};

// Sandboxed Lua 5.4 host. The runtime library is selected explicitly and hashed; it is never
// searched on PATH. Every Lua API interaction runs on EventQueue's one script thread.
class LuaDebuggerRuntime final
{
public:
  struct Impl;
  LuaDebuggerRuntime(LuaDebuggerSession& session, LuaDebuggerReadProviders providers,
                     LuaDebuggerRuntimeLimits limits = {});
  ~LuaDebuggerRuntime();

  LuaDebuggerRuntime(const LuaDebuggerRuntime&) = delete;
  LuaDebuggerRuntime& operator=(const LuaDebuggerRuntime&) = delete;

  bool Load(std::string runtime_library, std::span<const u8> script, std::string canonical_name,
            std::string* error = nullptr);
  bool Reload(std::span<const u8> script, std::string canonical_name,
              std::string* error = nullptr);
  bool EvaluateConsole(std::span<const u8> command, std::string* error = nullptr);
  void Stop();

  bool Enqueue(LuaDebuggerEvent event, std::string* error = nullptr);
  void WaitUntilIdle();
  LuaDebuggerEventQueue& Events() { return m_events; }
  std::vector<std::string> TakeOutput();
  std::vector<std::string> TakeErrors();

  // C ABI thunks cannot be member functions. These narrow bridges are public only so the private
  // translation-unit thunks can recover their owning runtime; they are not debugger user APIs.
  Impl& InternalImpl() { return *m_impl; }
  const LuaDebuggerReadProviders& ReadProviders() const { return m_providers; }
  LuaDebuggerEventQueue& CallbackEvents() { return m_events; }
  LuaDebuggerSession& Session() { return m_session; }
  void RecordOutput(std::string record) { AppendOutput(std::move(record)); }

private:
  bool CreateStateAndRun(std::span<const u8> script, std::string_view name, std::string* error);
  void Dispatch(const LuaDebuggerCallbackRegistration& registration,
                const LuaDebuggerEvent& event);
  void AppendOutput(std::string record);
  void AppendError(std::string error);

  LuaDebuggerSession& m_session;
  LuaDebuggerReadProviders m_providers;
  LuaDebuggerRuntimeLimits m_limits;
  LuaDebuggerEventQueue m_events;
  std::unique_ptr<Impl> m_impl;
  std::mutex m_records_mutex;
  std::vector<std::string> m_output;
  std::vector<std::string> m_errors;
};
}  // namespace SoAL
