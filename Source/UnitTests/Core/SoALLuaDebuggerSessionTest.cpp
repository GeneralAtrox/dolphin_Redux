// SPDX-License-Identifier: GPL-2.0-or-later
#include <array>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "Core/SoAL/LuaDebuggerSession.h"

namespace
{
std::array<u8, 32> RuntimeHash()
{
  std::array<u8, 32> hash{};
  hash[0] = 1;
  return hash;
}
}  // namespace

TEST(SoALLuaDebuggerSession, CleanImmutableLoadRemainsAuthoritative)
{
  SoAL::LuaDebuggerSession session;
  const std::vector<u8> script{'r', 'e', 't', 'u', 'r', 'n', ' ', '1'};
  std::string error;
  ASSERT_TRUE(session.LoadInitialScript(script, "logo-fade.lua", RuntimeHash(), &error)) << error;
  EXPECT_TRUE(session.EligibleForAuthoritativeEvidence());
  EXPECT_FALSE(session.MutationEnabled());
  ASSERT_EQ(session.Actions().size(), 1u);
  EXPECT_NE(session.StatusToJson().find("\"authoritative_eligible\":true"), std::string::npos);
}
TEST(SoALLuaDebuggerSession, ReloadAndConsoleAreExploratory)
{
  SoAL::LuaDebuggerSession session;
  const std::vector<u8> initial{'a'};
  const std::vector<u8> reloaded{'b'};
  ASSERT_TRUE(session.LoadInitialScript(initial, "initial.lua", RuntimeHash()));
  ASSERT_TRUE(session.ReloadScript(reloaded, "reloaded.lua"));
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::ExploratoryReloaded);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
  const std::vector<u8> console{'p', 'r', 'i', 'n', 't', '(', '1', ')'};
  EXPECT_TRUE(session.RecordConsole(console));
  ASSERT_EQ(session.Actions().size(), 3u);
}

TEST(SoALLuaDebuggerSession, MutationIsExplicitLoggedAndIrreversible)
{
  SoAL::LuaDebuggerSession session;
  const std::vector<u8> script{'a'};
  ASSERT_TRUE(session.LoadInitialScript(script, "mutate.lua", RuntimeHash()));
  const std::array<u8, 1> byte{0x7f};
  EXPECT_FALSE(session.RecordMemoryWrite(0x80000000, byte));
  ASSERT_TRUE(session.EnableMutation("interactive research"));
  ASSERT_TRUE(session.RecordMemoryWrite(0x80000000, byte));
  ASSERT_TRUE(session.RecordRegisterWrite("r3", 0x1234));
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::NonAuthoritativeMutated);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
  ASSERT_TRUE(session.ReloadScript(script, "clean-looking.lua"));
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::NonAuthoritativeMutated);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
  EXPECT_NE(session.StatusToJson().find("non_authoritative_mutated"), std::string::npos);
}

TEST(SoALLuaDebuggerSession, RejectsAmbiguousOrUnidentifiedInitialInputs)
{
  SoAL::LuaDebuggerSession session;
  const std::vector<u8> script{'a'};
  std::array<u8, 32> zero{};
  EXPECT_FALSE(session.LoadInitialScript({}, "empty.lua", RuntimeHash()));
  EXPECT_FALSE(session.LoadInitialScript(script, "", RuntimeHash()));
  EXPECT_FALSE(session.LoadInitialScript(script, "script.lua", zero));
  EXPECT_TRUE(session.LoadInitialScript(script, "script.lua", RuntimeHash()));
  EXPECT_FALSE(session.LoadInitialScript(script, "second.lua", RuntimeHash()));
}

TEST(SoALLuaDebuggerSession, RuntimeFailureInvalidatesAuthoritativeEvidence)
{
  SoAL::LuaDebuggerSession session;
  const std::vector<u8> script{'a'};
  ASSERT_TRUE(session.LoadInitialScript(script, "failure.lua", RuntimeHash()));
  ASSERT_TRUE(session.RecordRuntimeFailure("callback failed"));
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::AuthoritativeInvalidated);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
  EXPECT_NE(session.StatusToJson().find("runtime_failure"), std::string::npos);
}
