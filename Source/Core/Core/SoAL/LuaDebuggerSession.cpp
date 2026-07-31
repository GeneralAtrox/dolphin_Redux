// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerSession.h"

#include <algorithm>
#include <limits>

#include <fmt/format.h>

#include "Core/SoAL/LuaDebuggerSha256.h"

namespace SoAL
{
namespace
{
bool IsZeroHash(const std::array<u8, 32>& hash)
{
  return std::ranges::all_of(hash, [](u8 value) { return value == 0; });
}

std::string Hex(const std::array<u8, 32>& hash)
{
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(hash.size() * 2);
  for (const u8 byte : hash)
  {
    result += digits[byte >> 4];
    result += digits[byte & 0x0f];
  }
  return result;
}

std::string Escape(std::string_view value)
{
  std::string result;
  result.reserve(value.size());
  for (const unsigned char byte : value)
  {
    switch (byte)
    {
    case '\\': result += "\\\\"; break;
    case '"': result += "\\\""; break;
    case '\n': result += "\\n"; break;
    case '\r': result += "\\r"; break;
    case '\t': result += "\\t"; break;
    default:
      if (byte < 0x20)
        result += fmt::format("\\u{:04x}", byte);
      else
        result += static_cast<char>(byte);
      break;
    }
  }
  return result;
}

const char* EvidenceName(LuaDebuggerEvidenceState state)
{
  switch (state)
  {
  case LuaDebuggerEvidenceState::AuthoritativeReadOnly: return "authoritative_read_only";
  case LuaDebuggerEvidenceState::ExploratoryReloaded: return "exploratory_reloaded";
  case LuaDebuggerEvidenceState::NonAuthoritativeMutated: return "non_authoritative_mutated";
  case LuaDebuggerEvidenceState::AuthoritativeInvalidated: return "authoritative_invalidated";
  }
  return "invalid";
}

const char* ActionName(LuaDebuggerActionKind kind)
{
  switch (kind)
  {
  case LuaDebuggerActionKind::ScriptLoaded: return "script_loaded";
  case LuaDebuggerActionKind::ScriptReloaded: return "script_reloaded";
  case LuaDebuggerActionKind::ConsoleEvaluated: return "console_evaluated";
  case LuaDebuggerActionKind::MutationEnabled: return "mutation_enabled";
  case LuaDebuggerActionKind::MemoryWritten: return "memory_written";
  case LuaDebuggerActionKind::RegisterWritten: return "register_written";
  case LuaDebuggerActionKind::RuntimeFailure: return "runtime_failure";
  }
  return "invalid";
}

bool ValidName(std::string_view name)
{
  return !name.empty() && name.size() <= 255 &&
         std::ranges::all_of(name, [](unsigned char byte) {
           return byte >= 0x20 && byte != 0x7f;
         });
}
}  // namespace

bool LuaDebuggerSession::Record(LuaDebuggerActionKind kind, std::span<const u8> payload,
                                std::string detail, std::string* error)
{
  if (m_actions.size() >= 100'000 || m_next_sequence == std::numeric_limits<u64>::max())
  {
    if (error)
      *error = "Lua debugger audit log capacity exhausted";
    return false;
  }
  m_actions.push_back({.sequence = m_next_sequence++,
                       .kind = kind,
                       .payload_sha256 = Sha256(payload),
                       .detail = std::move(detail)});
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerSession::LoadInitialScript(std::span<const u8> bytes, std::string canonical_name,
                                           std::array<u8, 32> runtime_sha256, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (m_loaded || bytes.empty() || !ValidName(canonical_name) || IsZeroHash(runtime_sha256))
  {
    if (error)
      *error = "Lua debugger initial script or runtime identity is invalid";
    return false;
  }
  m_script_name = std::move(canonical_name);
  m_script_sha256 = Sha256(bytes);
  m_runtime_sha256 = runtime_sha256;
  m_loaded = true;
  return Record(LuaDebuggerActionKind::ScriptLoaded, bytes, m_script_name, error);
}

bool LuaDebuggerSession::ReloadScript(std::span<const u8> bytes, std::string canonical_name,
                                      std::string* error)
{
  if (!RecordReloadAttempt(bytes, canonical_name, error))
    return false;
  return CommitReloadScript(bytes, std::move(canonical_name), error);
}

bool LuaDebuggerSession::RecordReloadAttempt(std::span<const u8> bytes,
                                             std::string canonical_name, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_loaded || bytes.empty() || !ValidName(canonical_name))
  {
    if (error)
      *error = "Lua debugger reload is invalid";
    return false;
  }
  if (m_evidence_state == LuaDebuggerEvidenceState::AuthoritativeReadOnly)
    m_evidence_state = LuaDebuggerEvidenceState::ExploratoryReloaded;
  return Record(LuaDebuggerActionKind::ScriptReloaded, bytes, std::move(canonical_name), error);
}

bool LuaDebuggerSession::CommitReloadScript(std::span<const u8> bytes,
                                            std::string canonical_name, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_loaded || bytes.empty() || !ValidName(canonical_name) ||
      m_evidence_state == LuaDebuggerEvidenceState::AuthoritativeReadOnly)
  {
    if (error)
      *error = "Lua debugger reload commit has no valid logged attempt";
    return false;
  }
  m_script_name = std::move(canonical_name);
  m_script_sha256 = Sha256(bytes);
  if (error)
    error->clear();
  return true;
}

bool LuaDebuggerSession::RecordConsole(std::span<const u8> bytes, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_loaded || bytes.empty())
  {
    if (error)
      *error = "Lua debugger console input is empty or no script is loaded";
    return false;
  }
  if (m_evidence_state == LuaDebuggerEvidenceState::AuthoritativeReadOnly)
    m_evidence_state = LuaDebuggerEvidenceState::ExploratoryReloaded;
  return Record(LuaDebuggerActionKind::ConsoleEvaluated, bytes, "console", error);
}

bool LuaDebuggerSession::EnableMutation(std::string reason, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_loaded || !ValidName(reason))
  {
    if (error)
      *error = "Lua debugger mutation reason is invalid or no script is loaded";
    return false;
  }
  m_mutation_enabled = true;
  m_evidence_state = LuaDebuggerEvidenceState::NonAuthoritativeMutated;
  return Record(LuaDebuggerActionKind::MutationEnabled,
                std::span<const u8>{reinterpret_cast<const u8*>(reason.data()), reason.size()},
                std::move(reason), error);
}

bool LuaDebuggerSession::RecordMemoryWrite(u32 address, std::span<const u8> bytes,
                                           std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_mutation_enabled || bytes.empty())
  {
    if (error)
      *error = "Lua debugger memory write requires explicit mutation mode and nonempty bytes";
    return false;
  }
  return Record(LuaDebuggerActionKind::MemoryWritten, bytes,
                fmt::format("address={:08x};size={}", address, bytes.size()), error);
}

bool LuaDebuggerSession::RecordRegisterWrite(std::string register_name, u64 value,
                                             std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_mutation_enabled || !ValidName(register_name))
  {
    if (error)
      *error = "Lua debugger register write requires explicit mutation mode and register name";
    return false;
  }
  const std::array<u8, sizeof(value)> bytes{
      static_cast<u8>(value >> 56), static_cast<u8>(value >> 48), static_cast<u8>(value >> 40),
      static_cast<u8>(value >> 32), static_cast<u8>(value >> 24), static_cast<u8>(value >> 16),
      static_cast<u8>(value >> 8), static_cast<u8>(value)};
  return Record(LuaDebuggerActionKind::RegisterWritten, bytes,
                fmt::format("register={};value={:016x}", register_name, value), error);
}

bool LuaDebuggerSession::RecordRuntimeFailure(std::string detail, std::string* error)
{
  std::lock_guard lock(m_mutex);
  if (!m_loaded || detail.empty())
  {
    if (error)
      *error = "Lua debugger runtime failure requires a loaded session and detail";
    return false;
  }
  if (m_evidence_state == LuaDebuggerEvidenceState::AuthoritativeReadOnly)
    m_evidence_state = LuaDebuggerEvidenceState::AuthoritativeInvalidated;
  return Record(LuaDebuggerActionKind::RuntimeFailure,
                std::span<const u8>{reinterpret_cast<const u8*>(detail.data()), detail.size()},
                std::move(detail), error);
}

bool LuaDebuggerSession::IsLoaded() const
{
  std::lock_guard lock(m_mutex);
  return m_loaded;
}

bool LuaDebuggerSession::MutationEnabled() const
{
  std::lock_guard lock(m_mutex);
  return m_mutation_enabled;
}

LuaDebuggerEvidenceState LuaDebuggerSession::EvidenceState() const
{
  std::lock_guard lock(m_mutex);
  return m_evidence_state;
}

std::array<u8, 32> LuaDebuggerSession::ScriptSha256() const
{
  std::lock_guard lock(m_mutex);
  return m_script_sha256;
}

std::array<u8, 32> LuaDebuggerSession::RuntimeSha256() const
{
  std::lock_guard lock(m_mutex);
  return m_runtime_sha256;
}

std::vector<LuaDebuggerAction> LuaDebuggerSession::Actions() const
{
  std::lock_guard lock(m_mutex);
  return m_actions;
}

bool LuaDebuggerSession::EligibleForAuthoritativeEvidence() const
{
  std::lock_guard lock(m_mutex);
  return EligibleForAuthoritativeEvidenceLocked();
}

bool LuaDebuggerSession::EligibleForAuthoritativeEvidenceLocked() const
{
  return m_loaded && m_evidence_state == LuaDebuggerEvidenceState::AuthoritativeReadOnly &&
         !m_mutation_enabled;
}

std::string LuaDebuggerSession::StatusToJson() const
{
  std::lock_guard lock(m_mutex);
  std::string actions;
  for (const LuaDebuggerAction& action : m_actions)
  {
    if (!actions.empty())
      actions += ',';
    actions += fmt::format(
        "{{\"sequence\":{},\"kind\":\"{}\",\"payload_sha256\":\"{}\",\"detail\":\"{}\"}}",
        action.sequence, ActionName(action.kind), Hex(action.payload_sha256), Escape(action.detail));
  }
  return fmt::format(
      "{{\"schema\":\"soal.lua-debugger-session.v1\",\"loaded\":{},"
      "\"script_name\":\"{}\",\"script_sha256\":\"{}\",\"runtime_sha256\":\"{}\","
      "\"evidence_state\":\"{}\",\"authoritative_eligible\":{},"
      "\"mutation_enabled\":{},\"action_count\":{},\"actions\":[{}]}}",
      m_loaded, Escape(m_script_name), Hex(m_script_sha256), Hex(m_runtime_sha256),
      EvidenceName(m_evidence_state), EligibleForAuthoritativeEvidenceLocked(), m_mutation_enabled,
      m_actions.size(), actions);
}
}  // namespace SoAL
