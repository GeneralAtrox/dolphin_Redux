// SPDX-License-Identifier: GPL-2.0-or-later
#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "Core/SoAL/LuaDebuggerRuntime.h"

namespace
{
std::string LuaRuntimePath()
{
  const char* path = std::getenv("SOAL_TEST_LUA_RUNTIME");
  return path ? path : "";
}
}  // namespace

TEST(SoALLuaDebuggerRuntime, SandboxedTypedReadCallbackAndStructuredOutput)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP() << "Set SOAL_TEST_LUA_RUNTIME to the pinned Lua 5.4 runtime";

  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerReadProviders providers;
  providers.memory = [](u32 address, u32 size, std::vector<u8>* bytes) {
    if (address != 0x80000000 || size != 2)
      return false;
    *bytes = {0x12, 0x34};
    return true;
  };
  providers.reg = [](std::string_view name, u64* value) {
    if (name != "r3")
      return false;
    *value = 7;
    return true;
  };
  providers.symbol = [](std::string_view name, u32* address) {
    if (name != "logo_alpha")
      return false;
    *address = 0x80000000;
    return true;
  };
  SoAL::LuaDebuggerRuntime runtime(session, std::move(providers));
  const std::string script = R"(
    assert(io == nil and os == nil and package == nil and debug == nil)
    assert(load == nil and loadfile == nil and dofile == nil and require == nil)
    function frame(event)
      local address = soal.symbol("logo_alpha")
      local value = soal.read_u16(address)
      local r3 = soal.read_register("r3")
      soal.emit("frame", '{"alpha":' .. value .. ',"r3":' .. r3 .. '}')
    end
    soal.on_frame("frame")
  )";
  std::string error;
  ASSERT_TRUE(runtime.Load(runtime_path, std::span<const u8>(
                       reinterpret_cast<const u8*>(script.data()), script.size()),
                           "typed-read.lua", &error)) << error;
  EXPECT_TRUE(session.EligibleForAuthoritativeEvidence());
  ASSERT_TRUE(runtime.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 100, 1}, &error)) << error;
  runtime.WaitUntilIdle();
  const std::vector<std::string> output = runtime.TakeOutput();
  ASSERT_EQ(output.size(), 1u);
  EXPECT_NE(output[0].find("\"alpha\":4660"), std::string::npos);
  EXPECT_NE(output[0].find("\"r3\":7"), std::string::npos);
  EXPECT_TRUE(runtime.TakeErrors().empty());
}
TEST(SoALLuaDebuggerRuntime, RejectsBinaryChunksAndTaintsConsole)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntime runtime(session, {});
  const std::vector<u8> binary{0x1b, 'L', 'u', 'a'};
  EXPECT_FALSE(runtime.Load(runtime_path, binary, "bytecode.lua"));

  SoAL::LuaDebuggerSession clean_session;
  SoAL::LuaDebuggerRuntime clean(clean_session, {});
  const std::vector<u8> script{'x', ' ', '=', ' ', '1'};
  ASSERT_TRUE(clean.Load(runtime_path, script, "console.lua"));
  const std::vector<u8> command{'x', ' ', '=', ' ', '2'};
  ASSERT_TRUE(clean.EvaluateConsole(command));
  EXPECT_EQ(clean_session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::ExploratoryReloaded);
  EXPECT_FALSE(clean_session.EligibleForAuthoritativeEvidence());
}

TEST(SoALLuaDebuggerRuntime, MutationWritesRequireExplicitIrreversibleMode)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  u32 written_address = 0;
  std::vector<u8> written_bytes;
  std::string written_register;
  u64 written_value = 0;
  SoAL::LuaDebuggerReadProviders providers;
  providers.write_memory = [&](u32 address, std::span<const u8> bytes) {
    written_address = address;
    written_bytes.assign(bytes.begin(), bytes.end());
    return true;
  };
  providers.write_reg = [&](std::string_view name, u64 value) {
    written_register = name;
    written_value = value;
    return true;
  };
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntime runtime(session, std::move(providers));
  const std::vector<u8> script{'x', ' ', '=', ' ', '1'};
  ASSERT_TRUE(runtime.Load(runtime_path, script, "mutation.lua"));
  const std::string rejected = "soal.write_u16(0x80000000, 0x1234)";
  EXPECT_FALSE(runtime.EvaluateConsole(std::span<const u8>(
      reinterpret_cast<const u8*>(rejected.data()), rejected.size())));
  EXPECT_TRUE(written_bytes.empty());
  ASSERT_TRUE(session.EnableMutation("unit-test research"));
  const std::string accepted =
      "soal.write_u16(0x80000000, 0x1234); soal.write_register('r3', 9)";
  ASSERT_TRUE(runtime.EvaluateConsole(std::span<const u8>(
      reinterpret_cast<const u8*>(accepted.data()), accepted.size())));
  EXPECT_EQ(written_address, 0x80000000u);
  EXPECT_EQ(written_bytes, (std::vector<u8>{0x12, 0x34}));
  EXPECT_EQ(written_register, "r3");
  EXPECT_EQ(written_value, 9u);
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::NonAuthoritativeMutated);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
}

TEST(SoALLuaDebuggerRuntime, OutputCapacityFailureInvalidatesEvidence)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntimeLimits limits;
  limits.output_records = 1;
  SoAL::LuaDebuggerRuntime runtime(session, {}, limits);
  const std::string script = R"(
    function frame(event)
      soal.emit("first", '{"value":1}')
      soal.emit("second", '{"value":2}')
    end
    soal.on_frame("frame")
  )";
  std::string error;
  ASSERT_TRUE(runtime.Load(runtime_path,
                           std::span<const u8>(reinterpret_cast<const u8*>(script.data()),
                                               script.size()),
                           "capacity.lua", &error)) << error;
  ASSERT_TRUE(runtime.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 100, 1}, &error)) << error;
  runtime.WaitUntilIdle();
  EXPECT_EQ(runtime.TakeOutput().size(), 1u);
  const std::vector<std::string> errors = runtime.TakeErrors();
  ASSERT_EQ(errors.size(), 1u);
  EXPECT_EQ(errors[0], "Lua structured output capacity exhausted");
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::AuthoritativeInvalidated);
  EXPECT_FALSE(session.EligibleForAuthoritativeEvidence());
}

TEST(SoALLuaDebuggerRuntime, RegistersAndDispatchesEveryCallbackKindWithAddressFilters)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntime runtime(session, {});
  const std::string script = R"(
    local function emit_kind(event)
      soal.emit(event.kind, '{"ordinal":' .. event.source_ordinal .. '}')
    end
    function instruction(event) emit_kind(event) end
    function frame(event) emit_kind(event) end
    function memory_read(event) emit_kind(event) end
    function memory_write(event) emit_kind(event) end
    function present(event)
      soal.emit(event.kind, '{"ordinal":' .. event.source_ordinal ..
        ',"pixel_hash_valid":' .. event.present_pixel_hash_valid ..
        ',"pixel_hash_size":' .. #event.present_pixel_sha256 .. '}')
    end
    function gx(event)
      soal.emit(event.kind, '{"ordinal":' .. event.source_ordinal ..
        ',"prefix_size":' .. event.gx_prefix_size ..
        ',"payload_size":' .. event.gx_payload_size ..
        ',"payload_first":' .. string.byte(event.gx_payload, 1) ..
        ',"payload_last":' .. string.byte(event.gx_payload, -1) .. '}')
    end
    function draw(event)
      soal.emit(event.kind, '{"command":' .. event.gx_command_ordinal ..
        ',"draw":' .. event.gx_draw_ordinal ..
        ',"frame_draw":' .. event.gx_frame_draw_ordinal ..
        ',"title_state":' .. event.title_state ..
        ',"state_size":' .. event.gx_state_payload_size .. '}')
    end
    function copy(event)
      soal.emit(event.kind, '{"resource":' .. event.render_resource_id ..
        ',"address":' .. event.xfb_address .. '}')
    end
    soal.on_instruction(0x80001000, 0x8000100f, "instruction")
    soal.on_frame("frame")
    soal.on_memory_read(0x80002000, 0x80002003, "memory_read")
    soal.on_memory_write(0x80003000, 0x80003003, "memory_write")
    soal.on_present("present")
    soal.on_gx_command(0x61, 0x61, "gx")
    soal.on_gx_draw("draw")
    soal.on_efb_copy("copy")
  )";
  std::string error;
  ASSERT_TRUE(runtime.Load(runtime_path,
                           std::span<const u8>(reinterpret_cast<const u8*>(script.data()),
                                               script.size()),
                           "callbacks.lua", &error)) << error;
  const std::array events{
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::Instruction, 1, 1, 0x80001008},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::Instruction, 1, 2, 0x80001100},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::Frame, 2, 3},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::MemoryRead, 3, 4, 0x80002002},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::MemoryRead, 3, 5, 0x80002100},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::MemoryWrite, 4, 6, 0x80003001},
      SoAL::LuaDebuggerEvent{SoAL::LuaDebuggerEventKind::Present, 5, 7},
      SoAL::LuaDebuggerEvent{.kind = SoAL::LuaDebuggerEventKind::GXCommand,
                             .emulated_ticks = 6,
                             .source_ordinal = 8,
                             .address = 0x61,
                             .value = 0x61,
                             .size = 5,
                             .gx_prefix = 0x6112345678,
                             .gx_prefix_size = 5,
                             .gx_payload = {0x61, 0x12, 0x34, 0x56, 0x78}},
      SoAL::LuaDebuggerEvent{.kind = SoAL::LuaDebuggerEventKind::GXDraw,
                             .emulated_ticks = 6,
                             .source_ordinal = 9,
                             .address = 0x98,
                             .value = 0x98,
                             .size = 3,
                             .gx_payload = {0x98, 0x00, 0x00},
                             .gx_state_payload = {0x53, 0x54},
                             .video_frame_ordinal = 4,
                             .gx_command_ordinal = 77,
                             .gx_draw_ordinal = 8,
                             .gx_frame_draw_ordinal = 2,
                             .presentation_snapshot_valid = true,
                             .title_state = 3},
      SoAL::LuaDebuggerEvent{.kind = SoAL::LuaDebuggerEventKind::EFBCopy,
                             .emulated_ticks = 7,
                             .source_ordinal = 10,
                             .render_resource_id = 99,
                             .xfb_address = 0x123400},
  };
  for (const auto& event : events)
    ASSERT_TRUE(runtime.Enqueue(event, &error)) << error;
  runtime.WaitUntilIdle();
  const std::vector<std::string> output = runtime.TakeOutput();
  ASSERT_EQ(output.size(), 8u);
  for (const std::string_view kind : {"instruction", "frame", "memory_read", "memory_write",
                                      "present", "gx_command", "gx_draw", "efb_copy"})
  {
    EXPECT_EQ(std::ranges::count_if(output, [kind](const std::string& record) {
                return record.find(std::string{"\"kind\":\""} + std::string{kind} + "\"") !=
                       std::string::npos;
              }),
              1);
  }
  EXPECT_TRUE(runtime.TakeErrors().empty());
  EXPECT_TRUE(session.EligibleForAuthoritativeEvidence());
  const auto gx_output = std::ranges::find_if(output, [](const std::string& record) {
    return record.find("\"kind\":\"gx_command\"") != std::string::npos;
  });
  ASSERT_NE(gx_output, output.end());
  EXPECT_NE(gx_output->find("\"prefix_size\":5"), std::string::npos);
  EXPECT_NE(gx_output->find("\"payload_size\":5"), std::string::npos);
  EXPECT_NE(gx_output->find("\"payload_first\":97"), std::string::npos);
  EXPECT_NE(gx_output->find("\"payload_last\":120"), std::string::npos);
  EXPECT_TRUE(std::ranges::any_of(output, [](const std::string& record) {
    return record.find("\"kind\":\"gx_draw\"") != std::string::npos &&
           record.find("\"command\":77") != std::string::npos &&
           record.find("\"state_size\":2") != std::string::npos;
  }));
  EXPECT_TRUE(std::ranges::any_of(output, [](const std::string& record) {
    return record.find("\"kind\":\"present\"") != std::string::npos &&
           record.find("\"pixel_hash_valid\":0") != std::string::npos &&
           record.find("\"pixel_hash_size\":32") != std::string::npos;
  }));
}

TEST(SoALLuaDebuggerRuntime, FailedReloadIsLoggedButPreservesWorkingScriptAndIdentity)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntime runtime(session, {});
  const std::string initial = R"(
    function frame(event) soal.emit("original", '{"alive":true}') end
    soal.on_frame("frame")
  )";
  std::string error;
  ASSERT_TRUE(runtime.Load(runtime_path,
                           std::span<const u8>(reinterpret_cast<const u8*>(initial.data()),
                                               initial.size()),
                           "original.lua", &error)) << error;
  const auto original_hash = session.ScriptSha256();
  const std::string invalid = "function broken(";
  EXPECT_FALSE(runtime.Reload(
      std::span<const u8>(reinterpret_cast<const u8*>(invalid.data()), invalid.size()),
      "invalid.lua", &error));
  EXPECT_FALSE(error.empty());
  EXPECT_EQ(session.ScriptSha256(), original_hash);
  EXPECT_EQ(session.EvidenceState(), SoAL::LuaDebuggerEvidenceState::ExploratoryReloaded);
  ASSERT_EQ(session.Actions().size(), 2u);
  EXPECT_EQ(session.Actions()[1].kind, SoAL::LuaDebuggerActionKind::ScriptReloaded);
  ASSERT_TRUE(runtime.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 1, 1}, &error)) << error;
  runtime.WaitUntilIdle();
  const std::vector<std::string> output = runtime.TakeOutput();
  ASSERT_EQ(output.size(), 1u);
  EXPECT_NE(output[0].find("\"kind\":\"original\""), std::string::npos);
  EXPECT_TRUE(runtime.TakeErrors().empty());
}

TEST(SoALLuaDebuggerRuntime, CallbackCanUnregisterItselfForBoundedOneShotProbe)
{
  const std::string runtime_path = LuaRuntimePath();
  if (runtime_path.empty())
    GTEST_SKIP();
  SoAL::LuaDebuggerSession session;
  SoAL::LuaDebuggerRuntime runtime(session, {});
  const std::string script = R"(
    local registration
    function once(event)
      soal.emit("once", '{"seen":true}')
      soal.unregister(registration)
    end
    registration = soal.on_memory_read(0, 0xffffffff, "once")
  )";
  std::string error;
  ASSERT_TRUE(runtime.Load(runtime_path,
                           std::span<const u8>(reinterpret_cast<const u8*>(script.data()),
                                               script.size()),
                           "one-shot.lua", &error)) << error;
  ASSERT_TRUE(runtime.Enqueue(
      {SoAL::LuaDebuggerEventKind::MemoryRead, 1, 1, 0x80000000}, &error)) << error;
  runtime.WaitUntilIdle();
  ASSERT_TRUE(runtime.Enqueue(
      {SoAL::LuaDebuggerEventKind::MemoryRead, 2, 2, 0x80000004}, &error)) << error;
  runtime.WaitUntilIdle();
  EXPECT_EQ(runtime.TakeOutput().size(), 1u);
  EXPECT_TRUE(runtime.TakeErrors().empty());
  EXPECT_FALSE(runtime.Events().HasRegistrationKind(SoAL::LuaDebuggerEventKind::MemoryRead));
}
