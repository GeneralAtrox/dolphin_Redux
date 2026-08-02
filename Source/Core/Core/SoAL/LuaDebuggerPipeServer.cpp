// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerPipeServer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include <fmt/format.h>
#include <mbedtls/sha256.h>

#include "Common/Config/Config.h"
#include "Common/CommonTypes.h"
#include "Common/FileUtil.h"
#include "Common/SymbolDB.h"
#include "Core/Config/MainSettings.h"
#include "Core/Core.h"
#include "Core/CoreTiming.h"
#include "Core/Debugger/BranchWatch.h"
#include "Core/PowerPC/JitCommon/JitCache.h"
#include "Core/PowerPC/JitInterface.h"
#include "Core/PowerPC/PPCSymbolDB.h"
#include "Core/PowerPC/PowerPC.h"
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

std::string Sha256Hex(const std::array<u8, 32>& digest)
{
  std::string result;
  result.reserve(64);
  for (const u8 byte : digest)
    result += fmt::format("{:02x}", byte);
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
  if (normalized == "jit profile reset")
  {
    if (!Config::Get(Config::MAIN_DEBUG_JIT_ENABLE_PROFILING))
    {
      return "{\"ok\":false,\"action\":\"jit_profile_reset\","
             "\"error\":\"JitEnableProfiling was not enabled before boot\"}";
    }
    Core::System& system = Core::System::GetInstance();
    const Core::CPUThreadGuard guard(system);
    system.GetJitInterface().WipeBlockProfilingData(guard);
    return fmt::format(
        "{{\"ok\":true,\"action\":\"jit_profile_reset\",\"emulated_ticks\":{},"
        "\"error\":\"\"}}",
        system.GetCoreTiming().GetTicks());
  }
  if (normalized == "jit profile snapshot")
  {
    struct ExecutedBlock
    {
      u32 address = 0;
      u32 physical_address = 0;
      u32 size = 0;
      u32 feature_flags = 0;
      u64 run_count = 0;
      u64 cycles_spent = 0;
      std::string symbol;
      std::vector<u32> instruction_addresses;
      std::string code_bytes;
      std::string code_sha256;
      bool code_identity_available = false;
    };

    Core::System& system = Core::System::GetInstance();
    std::vector<ExecutedBlock> blocks;
    size_t total_blocks = 0;
    size_t profiled_blocks = 0;
    size_t unprofiled_blocks = 0;
    size_t code_identity_blocks = 0;
    u64 snapshot_ticks = 0;
    {
      const Core::CPUThreadGuard guard(system);
      snapshot_ticks = system.GetCoreTiming().GetTicks();
      system.GetJitInterface().RunOnBlocks(guard, [&](const JitBlock& block) {
        ++total_blocks;
        if (!block.profile_data)
        {
          ++unprofiled_blocks;
          return;
        }
        ++profiled_blocks;
        if (block.profile_data->run_count == 0)
          return;
        const Common::Symbol* symbol =
            system.GetPPCSymbolDB().GetSymbolFromAddr(block.effectiveAddress);
        ExecutedBlock executed{
            .address = block.effectiveAddress,
            .physical_address = block.physicalAddress,
            .size = block.originalSize * static_cast<u32>(sizeof(UGeckoInstruction)),
            .feature_flags = static_cast<u32>(block.feature_flags),
            .run_count = static_cast<u64>(block.profile_data->run_count),
            .cycles_spent = block.profile_data->cycles_spent,
            .symbol = symbol ? symbol->name : std::string{},
        };
        if (block.originalSize != 0 && block.original_buffer.size() == block.originalSize)
        {
          std::vector<u8> code_bytes;
          code_bytes.reserve(block.original_buffer.size() * sizeof(UGeckoInstruction));
          executed.instruction_addresses.reserve(block.original_buffer.size());
          executed.code_bytes.reserve(block.original_buffer.size() * 8);
          for (const auto& [address, instruction] : block.original_buffer)
          {
            executed.instruction_addresses.push_back(address);
            executed.code_bytes += fmt::format("{:08x}", instruction.hex);
            code_bytes.push_back(static_cast<u8>(instruction.hex >> 24));
            code_bytes.push_back(static_cast<u8>(instruction.hex >> 16));
            code_bytes.push_back(static_cast<u8>(instruction.hex >> 8));
            code_bytes.push_back(static_cast<u8>(instruction.hex));
          }
          std::array<u8, 32> digest{};
          if (mbedtls_sha256_ret(code_bytes.data(), code_bytes.size(), digest.data(), 0) == 0)
          {
            executed.code_sha256 = Sha256Hex(digest);
            executed.code_identity_available = true;
            ++code_identity_blocks;
          }
        }
        blocks.push_back(std::move(executed));
      });
    }
    std::ranges::sort(blocks, [](const ExecutedBlock& left, const ExecutedBlock& right) {
      return std::tie(left.address, left.physical_address, left.feature_flags) <
             std::tie(right.address, right.physical_address, right.feature_flags);
    });
    std::string block_json = "[";
    for (size_t index = 0; index < blocks.size(); ++index)
    {
      const ExecutedBlock& block = blocks[index];
      if (index != 0)
        block_json += ',';
      std::string instruction_addresses = "[";
      for (size_t instruction_index = 0;
           instruction_index < block.instruction_addresses.size(); ++instruction_index)
      {
        if (instruction_index != 0)
          instruction_addresses += ',';
        instruction_addresses +=
            fmt::format("\"{:08x}\"", block.instruction_addresses[instruction_index]);
      }
      instruction_addresses += ']';
      block_json += fmt::format(
          "{{\"ppc_address\":\"{:08x}\",\"physical_address\":\"{:08x}\","
          "\"ppc_size\":{},\"feature_flags\":{},\"run_count\":{},"
          "\"cycles_spent\":{},\"symbol\":\"{}\","
          "\"code_identity_available\":{},\"instruction_addresses\":{},"
          "\"code_bytes\":\"{}\",\"code_sha256\":\"{}\"}}",
          block.address, block.physical_address, block.size, block.feature_flags,
          block.run_count, block.cycles_spent, EscapeJson(block.symbol),
          block.code_identity_available ? "true" : "false", instruction_addresses,
          block.code_bytes, block.code_sha256);
    }
    block_json += ']';
    return fmt::format(
        "{{\"ok\":true,\"action\":\"jit_profile_snapshot\","
        "\"schema\":\"dolphin-redux.jit-profile.v2\",\"emulated_ticks\":{},"
        "\"profiling_enabled\":{},\"total_blocks\":{},\"profiled_blocks\":{},"
        "\"unprofiled_blocks\":{},\"executed_blocks\":{},"
        "\"code_identity_blocks\":{},\"code_identity_complete\":{},\"blocks\":{}}}",
        snapshot_ticks,
        Config::Get(Config::MAIN_DEBUG_JIT_ENABLE_PROFILING) ? "true" : "false",
        total_blocks, profiled_blocks, unprofiled_blocks, blocks.size(), code_identity_blocks,
        code_identity_blocks == blocks.size() ? "true" : "false", block_json);
  }
  if (normalized == "branch profile reset")
  {
    Core::System& system = Core::System::GetInstance();
    u64 reset_ticks = 0;
    u32 reset_pc = 0;
    {
      const Core::CPUThreadGuard guard(system);
      Core::BranchWatch& branch_watch = system.GetPowerPC().GetBranchWatch();
      branch_watch.Clear(guard);
      if (!branch_watch.GetRecordingActive())
        branch_watch.SetRecordingActive(guard, true);
      reset_ticks = system.GetCoreTiming().GetTicks();
      reset_pc = system.GetPPCState().pc;
    }
    return fmt::format(
        "{{\"ok\":true,\"action\":\"branch_profile_reset\","
        "\"schema\":\"dolphin-redux.branch-profile-boundary.v1\","
        "\"emulated_ticks\":{},\"pc\":\"{:08x}\",\"recording_active\":true}}",
        reset_ticks, reset_pc);
  }
  if (normalized == "branch profile snapshot")
  {
    Core::System& system = Core::System::GetInstance();
    std::vector<Core::BranchWatchSnapshotEntry> entries;
    u64 snapshot_ticks = 0;
    bool recording_active = false;
    {
      const Core::CPUThreadGuard guard(system);
      const Core::BranchWatch& branch_watch = system.GetPowerPC().GetBranchWatch();
      snapshot_ticks = system.GetCoreTiming().GetTicks();
      recording_active = branch_watch.GetRecordingActive();
      entries = branch_watch.Snapshot(guard);
    }
    std::ranges::sort(entries, [](const auto& left, const auto& right) {
      return std::tie(left.origin_addr, left.destin_addr, left.original_inst, left.is_virtual,
                      left.condition) <
             std::tie(right.origin_addr, right.destin_addr, right.original_inst,
                      right.is_virtual, right.condition);
    });
    u64 total_hits = 0;
    size_t taken_edges = 0;
    size_t not_taken_edges = 0;
    std::string entries_json = "[";
    for (size_t index = 0; index < entries.size(); ++index)
    {
      const Core::BranchWatchSnapshotEntry& entry = entries[index];
      total_hits += entry.total_hits;
      if (entry.condition)
        ++taken_edges;
      else
        ++not_taken_edges;
      if (index != 0)
        entries_json += ',';
      entries_json += fmt::format(
          "{{\"origin\":\"{:08x}\",\"destination\":\"{:08x}\","
          "\"instruction\":\"{:08x}\",\"hits\":{},\"taken\":{},"
          "\"address_space\":\"{}\"}}",
          entry.origin_addr, entry.destin_addr, entry.original_inst, entry.total_hits,
          entry.condition ? "true" : "false", entry.is_virtual ? "virtual" : "physical");
    }
    entries_json += ']';
    return fmt::format(
        "{{\"ok\":true,\"action\":\"branch_profile_snapshot\","
        "\"schema\":\"dolphin-redux.branch-profile.v1\",\"emulated_ticks\":{},"
        "\"recording_active\":{},\"distinct_edges\":{},\"taken_edges\":{},"
        "\"not_taken_edges\":{},\"total_hits\":{},\"edges\":{}}}",
        snapshot_ticks, recording_active ? "true" : "false", entries.size(), taken_edges,
        not_taken_edges, total_hits, entries_json);
  }
  if (normalized == "branch profile stop")
  {
    Core::System& system = Core::System::GetInstance();
    u64 stop_ticks = 0;
    {
      const Core::CPUThreadGuard guard(system);
      Core::BranchWatch& branch_watch = system.GetPowerPC().GetBranchWatch();
      if (branch_watch.GetRecordingActive())
        branch_watch.SetRecordingActive(guard, false);
      stop_ticks = system.GetCoreTiming().GetTicks();
    }
    return fmt::format(
        "{{\"ok\":true,\"action\":\"branch_profile_stop\",\"emulated_ticks\":{},"
        "\"recording_active\":false}}",
        stop_ticks);
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
