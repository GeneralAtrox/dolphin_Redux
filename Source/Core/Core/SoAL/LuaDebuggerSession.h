// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "Common/CommonTypes.h"

namespace SoAL
{
enum class LuaDebuggerEvidenceState : u8
{
  AuthoritativeReadOnly,
  ExploratoryReloaded,
  NonAuthoritativeMutated,
  AuthoritativeInvalidated,
};

enum class LuaDebuggerActionKind : u8
{
  ScriptLoaded,
  ScriptReloaded,
  ConsoleEvaluated,
  MutationEnabled,
  MemoryWritten,
  RegisterWritten,
  RuntimeFailure,
};

struct LuaDebuggerAction
{
  u64 sequence = 0;
  LuaDebuggerActionKind kind = LuaDebuggerActionKind::ScriptLoaded;
  std::array<u8, 32> payload_sha256{};
  std::string detail;
};

// Owns the provenance state shared by the Lua runtime, callback dispatcher, debugger controls and
// control-server console. It deliberately contains no Lua API types so the evidence contract can be
// unit-tested independently of the selected pinned Lua runtime.
class LuaDebuggerSession
{
public:
  bool LoadInitialScript(std::span<const u8> bytes, std::string canonical_name,
                         std::array<u8, 32> runtime_sha256, std::string* error = nullptr);
  bool ReloadScript(std::span<const u8> bytes, std::string canonical_name,
                    std::string* error = nullptr);
  // Runtime reload is transactional: the attempt is permanently logged/tainted first, while the
  // active script identity changes only after the replacement sandbox has started successfully.
  bool RecordReloadAttempt(std::span<const u8> bytes, std::string canonical_name,
                           std::string* error = nullptr);
  bool CommitReloadScript(std::span<const u8> bytes, std::string canonical_name,
                          std::string* error = nullptr);
  bool RecordConsole(std::span<const u8> bytes, std::string* error = nullptr);
  bool EnableMutation(std::string reason, std::string* error = nullptr);
  bool RecordMemoryWrite(u32 address, std::span<const u8> bytes, std::string* error = nullptr);
  bool RecordRegisterWrite(std::string register_name, u64 value,
                           std::string* error = nullptr);
  bool RecordRuntimeFailure(std::string detail, std::string* error = nullptr);

  bool IsLoaded() const;
  bool MutationEnabled() const;
  bool EligibleForAuthoritativeEvidence() const;
  LuaDebuggerEvidenceState EvidenceState() const;
  std::array<u8, 32> ScriptSha256() const;
  std::array<u8, 32> RuntimeSha256() const;
  std::vector<LuaDebuggerAction> Actions() const;
  std::string StatusToJson() const;

private:
  bool Record(LuaDebuggerActionKind kind, std::span<const u8> payload, std::string detail,
              std::string* error);
  bool EligibleForAuthoritativeEvidenceLocked() const;

  mutable std::mutex m_mutex;
  bool m_loaded = false;
  bool m_mutation_enabled = false;
  LuaDebuggerEvidenceState m_evidence_state =
      LuaDebuggerEvidenceState::AuthoritativeReadOnly;
  u64 m_next_sequence = 0;
  std::string m_script_name;
  std::array<u8, 32> m_script_sha256{};
  std::array<u8, 32> m_runtime_sha256{};
  std::vector<LuaDebuggerAction> m_actions;
};
}  // namespace SoAL
