// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerPipeServer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include "Common/CommonTypes.h"
#include "Common/FileUtil.h"
#include "Core/SoAL/LuaDebuggerService.h"
#include "Core/System.h"

#ifdef _WIN32
#include <Windows.h>
#endif

namespace SoAL
{
namespace
{
std::string EscapeJson(std::string_view value)
{
  std::string result;
  result.reserve(value.size());
  for (const unsigned char c : value)
  {
    if (c == '\\' || c == '"')
      result += '\\';
    if (c >= 0x20)
      result += static_cast<char>(c);
    else if (c == '\n')
      result += "\\n";
  }
  return result;
}

std::string StringArrayJson(const std::vector<std::string>& values)
{
  std::string result = "[";
  for (size_t i = 0; i < values.size(); ++i)
  {
    if (i != 0)
      result += ',';
    result += fmt::format("\"{}\"", EscapeJson(values[i]));
  }
  return result + ']';
}

std::string RawObjectArrayJson(const std::vector<std::string>& values)
{
  std::string result = "[";
  for (size_t i = 0; i < values.size(); ++i)
  {
    if (i != 0)
      result += ',';
    result += values[i];
  }
  return result + ']';
}

std::optional<u32> ParseAddress(std::string_view text)
{
  if (text.starts_with("0x"))
    text.remove_prefix(2);
  u32 address = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), address, 16);
  if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    return std::nullopt;
  return address;
}

#ifdef _WIN32
std::optional<std::string> ReadMessage(HANDLE pipe, std::string* error)
{
  constexpr size_t MAX_COMMAND_BYTES = 4 * 1024 * 1024;
  std::array<char, 4096> buffer{};
  std::string command;
  for (;;)
  {
    DWORD bytes_read = 0;
    const BOOL complete =
        ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr);
    if (bytes_read != 0)
    {
      if (command.size() + bytes_read > MAX_COMMAND_BYTES)
      {
        *error = "command exceeds 4 MiB protocol limit";
        return std::nullopt;
      }
      command.append(buffer.data(), bytes_read);
    }
    if (complete)
      return command;
    if (GetLastError() != ERROR_MORE_DATA)
    {
      *error = fmt::format("named-pipe read failed with Win32 error {}", GetLastError());
      return std::nullopt;
    }
  }
}
#endif
}  // namespace

LuaDebuggerPipeServer& LuaDebuggerPipeServer::Get()
{
  static LuaDebuggerPipeServer server;
  return server;
}

LuaDebuggerPipeServer::~LuaDebuggerPipeServer()
{
  Stop();
}

void LuaDebuggerPipeServer::Start()
{
  Stop();
  m_pipe_name = "dolphin-redux";
  const char* requested = std::getenv("SOAL_PIPE_NAME");
  if (requested && *requested)
  {
    const std::string_view candidate{requested};
    if (candidate.size() <= 96 &&
        std::ranges::all_of(candidate, [](unsigned char c) {
          return std::isalnum(c) || c == '-' || c == '_' || c == '.';
        }))
    {
      m_pipe_name = candidate;
    }
  }
#ifdef _WIN32
  m_running = true;
  m_thread = std::thread(&LuaDebuggerPipeServer::Run, this);
#endif
}

void LuaDebuggerPipeServer::Stop()
{
  m_running = false;
#ifdef _WIN32
  if (m_thread.joinable())
  {
    const std::wstring path = L"\\\\.\\pipe\\" +
                              std::wstring(m_pipe_name.begin(), m_pipe_name.end());
    if (HANDLE pipe = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                  OPEN_EXISTING, 0, nullptr);
        pipe != INVALID_HANDLE_VALUE)
    {
      CloseHandle(pipe);
    }
    m_thread.join();
  }
#endif
  LuaDebuggerService::Get().Stop();
}

std::string LuaDebuggerPipeServer::HandleCommand(const std::string& command)
{
  std::string normalized = command;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (normalized.starts_with("lua start "))
  {
    const std::string arguments = command.substr(10);
    const size_t separator = arguments.find(" | ");
    if (separator == std::string::npos)
      return "{\"ok\":false,\"error\":\"usage: lua start <runtime-library> | <script>\"}";
    const std::string runtime_path = arguments.substr(0, separator);
    const std::string script_path = arguments.substr(separator + 3);
    std::string script;
    std::string error;
    if (runtime_path.empty() || script_path.empty() ||
        !File::ReadFileToString(script_path, script) || script.empty() ||
        script.size() > 4 * 1024 * 1024)
    {
      return "{\"ok\":false,\"error\":\"Lua script is missing, empty, or over 4 MiB\"}";
    }
    const bool ok = LuaDebuggerService::Get().Start(
        Core::System::GetInstance(), runtime_path,
        std::span<const u8>(reinterpret_cast<const u8*>(script.data()), script.size()),
        script_path, &error);
    return fmt::format("{{\"ok\":{},\"action\":\"lua_start\",\"error\":\"{}\"}}", ok,
                       EscapeJson(error));
  }
  if (normalized == "lua stop")
  {
    LuaDebuggerService::Get().Stop();
    return "{\"ok\":true,\"action\":\"lua_stop\"}";
  }
  if (normalized == "lua status")
    return fmt::format("{{\"ok\":true,\"session\":{}}}", LuaDebuggerService::Get().StatusJson());
  if (normalized == "lua output" || normalized == "lua errors")
  {
    const bool errors = normalized.ends_with("errors");
    const std::vector<std::string> records =
        errors ? LuaDebuggerService::Get().TakeErrors() : LuaDebuggerService::Get().TakeOutput();
    return fmt::format("{{\"ok\":true,\"action\":\"lua_{}\",\"records\":{}}}",
                       errors ? "errors" : "output",
                       errors ? StringArrayJson(records) : RawObjectArrayJson(records));
  }
  if (normalized.starts_with("lua reload "))
  {
    const std::string script_path = command.substr(11);
    std::string script;
    std::string error;
    const bool ok = File::ReadFileToString(script_path, script) && !script.empty() &&
                    script.size() <= 4 * 1024 * 1024 &&
                    LuaDebuggerService::Get().Reload(
                        std::span<const u8>(reinterpret_cast<const u8*>(script.data()),
                                            script.size()),
                        script_path, &error);
    if (script.empty() && error.empty())
      error = "Lua reload script is missing or empty";
    return fmt::format("{{\"ok\":{},\"action\":\"lua_reload\",\"error\":\"{}\"}}", ok,
                       EscapeJson(error));
  }
  if (normalized.starts_with("lua console "))
  {
    const std::string code = command.substr(12);
    std::string error;
    const bool ok = !code.empty() && LuaDebuggerService::Get().Console(
                                              std::span<const u8>(
                                                  reinterpret_cast<const u8*>(code.data()),
                                                  code.size()),
                                              &error);
    return fmt::format("{{\"ok\":{},\"action\":\"lua_console\",\"error\":\"{}\"}}", ok,
                       EscapeJson(error));
  }
  if (normalized.starts_with("lua mutation enable "))
  {
    std::string error;
    const bool ok = LuaDebuggerService::Get().EnableMutation(command.substr(20), &error);
    return fmt::format(
        "{{\"ok\":{},\"action\":\"lua_mutation_enable\",\"mutation_enabled\":{},"
        "\"warning\":\"NON-AUTHORITATIVE RESEARCH MODE\",\"error\":\"{}\"}}",
        ok, ok, EscapeJson(error));
  }
  if (normalized == "lua pause" || normalized == "lua resume" ||
      normalized == "lua step instruction" || normalized == "lua step frame")
  {
    std::string error;
    auto& debugger = LuaDebuggerService::Get();
    const bool ok = normalized == "lua pause"            ? debugger.Pause(&error) :
                    normalized == "lua resume"           ? debugger.Resume(&error) :
                    normalized == "lua step instruction" ? debugger.StepInstruction(&error) :
                                                            debugger.StepFrame(&error);
    return fmt::format("{{\"ok\":{},\"action\":\"{}\",\"error\":\"{}\"}}", ok,
                       EscapeJson(normalized), EscapeJson(error));
  }
  if (normalized == "lua breakpoint list")
  {
    const std::vector<u32> breakpoints = LuaDebuggerService::Get().Breakpoints();
    std::string values = "[";
    for (size_t i = 0; i < breakpoints.size(); ++i)
    {
      if (i != 0)
        values += ',';
      values += fmt::format("\"{:08x}\"", breakpoints[i]);
    }
    return fmt::format("{{\"ok\":true,\"breakpoints\":{}}}", values + ']');
  }
  if (normalized == "lua breakpoint clear")
  {
    LuaDebuggerService::Get().ClearBreakpoints();
    return "{\"ok\":true,\"action\":\"lua_breakpoint_clear\"}";
  }
  if (normalized.starts_with("lua breakpoint add ") ||
      normalized.starts_with("lua breakpoint remove "))
  {
    const bool add = normalized.starts_with("lua breakpoint add ");
    const size_t prefix = add ? 19 : 22;
    const std::optional<u32> address = ParseAddress(normalized.substr(prefix));
    std::string error;
    const bool ok = address && (add ? LuaDebuggerService::Get().AddBreakpoint(*address, &error) :
                                      LuaDebuggerService::Get().RemoveBreakpoint(*address, &error));
    if (!address)
      error = "Breakpoint address must be hexadecimal";
    return fmt::format(
        "{{\"ok\":{},\"action\":\"lua_breakpoint_{}\",\"address\":\"{}\","
        "\"error\":\"{}\"}}",
        ok, add ? "add" : "remove", address ? fmt::format("{:08x}", *address) : "",
        EscapeJson(error));
  }
  return "{\"ok\":false,\"error\":\"unknown command\"}";
}

void LuaDebuggerPipeServer::Run()
{
#ifdef _WIN32
  const std::wstring path =
      L"\\\\.\\pipe\\" + std::wstring(m_pipe_name.begin(), m_pipe_name.end());
  while (m_running)
  {
    HANDLE pipe = CreateNamedPipeW(path.c_str(), PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1,
                                   4 * 1024 * 1024, 4 * 1024 * 1024, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
      return;
    if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
      CloseHandle(pipe);
      continue;
    }
    std::string read_error;
    const std::optional<std::string> message = ReadMessage(pipe, &read_error);
    std::string reply;
    if (message)
    {
      std::string command = *message;
      while (!command.empty() && (command.back() == '\r' || command.back() == '\n'))
        command.pop_back();
      reply = HandleCommand(command);
    }
    else
    {
      reply = fmt::format("{{\"ok\":false,\"error\":\"{}\"}}", EscapeJson(read_error));
    }
    DWORD written = 0;
    WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &written, nullptr);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
#endif
}
}  // namespace SoAL
