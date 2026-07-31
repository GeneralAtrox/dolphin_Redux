// SPDX-License-Identifier: GPL-2.0-or-later
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "Core/SoAL/LuaDebuggerEvents.h"

TEST(SoALLuaDebuggerEvents, DispatchesInOrderOnOneOwnedThreadWithAddressFiltering)
{
  struct Delivery
  {
    u64 registration;
    u64 ordinal;
    std::thread::id thread;
  };
  std::mutex mutex;
  std::vector<Delivery> deliveries;
  SoAL::LuaDebuggerEventQueue queue(
      [&](const SoAL::LuaDebuggerCallbackRegistration& registration,
          const SoAL::LuaDebuggerEvent& event) {
        std::lock_guard lock(mutex);
        deliveries.push_back({registration.id, event.source_ordinal, std::this_thread::get_id()});
      });
  ASSERT_TRUE(queue.Start());
  u64 broad = 0;
  u64 narrow = 0;
  ASSERT_TRUE(queue.Register(SoAL::LuaDebuggerEventKind::Instruction,
                             SoAL::LuaDebuggerAddressFilter{0x80000000, 0x800000ff}, "broad", &broad));
  ASSERT_TRUE(queue.Register(SoAL::LuaDebuggerEventKind::Instruction,
                             SoAL::LuaDebuggerAddressFilter{0x80000010, 0x80000010}, "narrow", &narrow));
  ASSERT_TRUE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Instruction, 10, 1, 0x80000000}));
  ASSERT_TRUE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Instruction, 10, 2, 0x80000010}));
  queue.WaitUntilIdle();
  queue.Stop();

  ASSERT_EQ(deliveries.size(), 3u);
  EXPECT_EQ(deliveries[0].registration, broad);
  EXPECT_EQ(deliveries[0].ordinal, 1u);
  EXPECT_EQ(deliveries[1].registration, broad);
  EXPECT_EQ(deliveries[1].ordinal, 2u);
  EXPECT_EQ(deliveries[2].registration, narrow);
  EXPECT_EQ(deliveries[2].ordinal, 2u);
  EXPECT_NE(deliveries[0].thread, std::this_thread::get_id());
  EXPECT_EQ(deliveries[0].thread, deliveries[1].thread);
  EXPECT_EQ(deliveries[1].thread, deliveries[2].thread);
}
TEST(SoALLuaDebuggerEvents, RejectsAmbiguousFiltersAndNonMonotonicKeys)
{
  SoAL::LuaDebuggerEventQueue queue([](const auto&, const auto&) {});
  ASSERT_TRUE(queue.Start());
  EXPECT_FALSE(queue.Register(SoAL::LuaDebuggerEventKind::Frame,
                              SoAL::LuaDebuggerAddressFilter{1, 2}, "frame", nullptr));
  EXPECT_FALSE(queue.Register(SoAL::LuaDebuggerEventKind::Instruction,
                              SoAL::LuaDebuggerAddressFilter{2, 1}, "instruction", nullptr));
  EXPECT_FALSE(queue.Register(SoAL::LuaDebuggerEventKind::Instruction, std::nullopt, "bad-name!",
                              nullptr));
  ASSERT_TRUE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 1, 1}));
  EXPECT_FALSE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 1, 1}));
  EXPECT_TRUE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 0, 2}));
  EXPECT_FALSE(queue.Enqueue({SoAL::LuaDebuggerEventKind::Frame, 2, 2}));
  queue.WaitUntilIdle();
}

TEST(SoALLuaDebuggerEvents, RangedMemoryRegistrationExistsWithoutMatchingAddressZero)
{
  SoAL::LuaDebuggerEventQueue queue([](const auto&, const auto&) {});
  ASSERT_TRUE(queue.Start());
  ASSERT_TRUE(queue.Register(SoAL::LuaDebuggerEventKind::MemoryWrite,
                             SoAL::LuaDebuggerAddressFilter{0x80347504, 0x80347518},
                             "fade_write", nullptr));
  EXPECT_TRUE(queue.HasRegistrationKind(SoAL::LuaDebuggerEventKind::MemoryWrite));
  EXPECT_FALSE(queue.HasMatchingRegistration(SoAL::LuaDebuggerEventKind::MemoryWrite, 0));
  EXPECT_TRUE(
      queue.HasMatchingRegistration(SoAL::LuaDebuggerEventKind::MemoryWrite, 0x80347510));
}

TEST(SoALLuaDebuggerEvents, SynchronousMaintenanceUsesScriptThread)
{
  std::thread::id maintenance_thread;
  SoAL::LuaDebuggerEventQueue queue([](const auto&, const auto&) {});
  ASSERT_TRUE(queue.Start());
  ASSERT_TRUE(queue.ExecuteSync([&] { maintenance_thread = std::this_thread::get_id(); }));
  EXPECT_NE(maintenance_thread, std::this_thread::get_id());
}

TEST(SoALLuaDebuggerEvents, RejectsIncompleteGXPayload)
{
  SoAL::LuaDebuggerEventQueue queue([](const auto&, const auto&) {});
  ASSERT_TRUE(queue.Start());
  std::string error;
  EXPECT_FALSE(queue.Enqueue({.kind = SoAL::LuaDebuggerEventKind::GXCommand,
                              .emulated_ticks = 1,
                              .source_ordinal = 1,
                              .address = 0x10,
                              .size = 9,
                              .gx_payload = {0x10}},
                             &error));
  EXPECT_EQ(error, "Lua debugger GX payload is incomplete or exceeds its bound");
  EXPECT_TRUE(queue.Enqueue({.kind = SoAL::LuaDebuggerEventKind::GXCommand,
                             .emulated_ticks = 1,
                             .source_ordinal = 1,
                             .address = 0x10,
                             .size = 2,
                             .gx_payload = {0x10, 0x00}},
                            &error)) << error;
  queue.WaitUntilIdle();
}

TEST(SoALLuaDebuggerEvents, GXDrawOwnsCompleteCommandAndStatePayloads)
{
  std::vector<SoAL::LuaDebuggerEvent> deliveries;
  SoAL::LuaDebuggerEventQueue queue(
      [&](const auto&, const SoAL::LuaDebuggerEvent& event) { deliveries.push_back(event); });
  ASSERT_TRUE(queue.Start());
  ASSERT_TRUE(queue.Register(SoAL::LuaDebuggerEventKind::GXDraw, std::nullopt, "draw", nullptr));
  std::string error;
  EXPECT_FALSE(queue.Enqueue({.kind = SoAL::LuaDebuggerEventKind::GXDraw,
                              .emulated_ticks = 1,
                              .source_ordinal = 1,
                              .address = 0x98,
                              .size = 4,
                              .gx_payload = {0x98, 0x00, 0x01}},
                             &error));
  EXPECT_EQ(error, "Lua debugger GX payload is incomplete or exceeds its bound");
  ASSERT_TRUE(queue.Enqueue({.kind = SoAL::LuaDebuggerEventKind::GXDraw,
                             .emulated_ticks = 1,
                             .source_ordinal = 1,
                             .address = 0x98,
                             .size = 3,
                             .gx_payload = {0x98, 0x00, 0x00},
                             .gx_state_payload = {0x53, 0x54},
                             .gx_command_ordinal = 7,
                             .gx_draw_ordinal = 2},
                            &error)) << error;
  queue.WaitUntilIdle();
  queue.Stop();
  ASSERT_EQ(deliveries.size(), 1u);
  EXPECT_EQ(deliveries[0].gx_command_ordinal, 7u);
  EXPECT_EQ(deliveries[0].gx_draw_ordinal, 2u);
  EXPECT_EQ(deliveries[0].gx_state_payload, (std::vector<u8>{0x53, 0x54}));
}
