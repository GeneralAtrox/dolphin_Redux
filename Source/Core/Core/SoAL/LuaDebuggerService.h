// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <memory>
#include <atomic>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "Common/CommonTypes.h"
#include "Core/SoAL/LuaDebuggerEvents.h"

namespace Core
{
class System;
}

namespace SoAL
{
struct LuaDebuggerEfbCopyInfo
{
  u32 destination_address = 0;
  u32 destination_stride = 0;
  u32 copy_width = 0;
  u32 copy_height = 0;
  u32 source_left = 0;
  u32 source_top = 0;
  u32 source_right = 0;
  u32 source_bottom = 0;
  std::array<u32, 3> vram_filter_coefficients{};
  u32 gamma_bits = 0;
  u32 y_scale_bits = 0;
  u32 copy_parameter_flags = 0;
  u64 resource_id = 0;
  u64 resource_hash = 0;
  u64 resource_base_hash = 0;
  u32 resource_content_ordinal = 0;
  bool copy_to_vram = false;
  bool copy_to_ram = false;
  bool copy_to_xfb = false;
  bool depth_copy = false;
  bool raw_pixel_capture_valid = false;
  std::array<u8, 32> efb_source_pixels_sha256{};
  std::array<u8, 32> xfb_copy_pixels_sha256{};
  u32 captured_pixel_width = 0;
  u32 captured_pixel_height = 0;
  u32 captured_pixel_stride = 0;
  u32 captured_pixel_format = 0;
};

struct LuaDebuggerEffectivePipelineInfo
{
  u64 gx_draw_ordinal = 0;
  // 0 is non-indexed, 1 is indexed.
  u32 draw_kind = 0;
  u32 draw_base = 0;
  u32 draw_count = 0;
  u32 base_vertex = 0;
  std::vector<u8> definition;
  std::vector<u8> bindings;
};

class LuaDebuggerController;
class LuaDebuggerRuntime;
class LuaDebuggerSession;

// Process-wide debugger service used by CPU, memory and video hook sites. It is inactive unless an
// explicit control command supplies both a Lua runtime and script. Hook calls are then cheap,
// fail-closed enqueue attempts; errors remain available through the control surface.
class LuaDebuggerService final
{
public:
  static LuaDebuggerService& Get();

  bool Start(Core::System& system, std::string runtime_library, std::span<const u8> script,
             std::string canonical_name, std::string* error = nullptr);
  void Stop();
  bool IsActive() const;
  bool WantsMemoryHooks() const;
  bool WantsInstructionAt(u32 address) const;
  bool WantsPresentObservation() const;
  bool WantsEffectivePipelineObservation() const;
  u64 LatestGXDrawOrdinal() const;

  bool Reload(std::span<const u8> script, std::string canonical_name,
              std::string* error = nullptr);
  bool Console(std::span<const u8> command, std::string* error = nullptr);
  bool EnableMutation(std::string reason, std::string* error = nullptr);
  std::string StatusJson() const;
  std::vector<std::string> TakeOutput();
  std::vector<std::string> TakeErrors();

  bool Pause(std::string* error = nullptr);
  bool Resume(std::string* error = nullptr);
  bool StepInstruction(std::string* error = nullptr);
  bool StepFrame(std::string* error = nullptr);
  bool AddBreakpoint(u32 address, std::string* error = nullptr);
  bool RemoveBreakpoint(u32 address, std::string* error = nullptr);
  void ClearBreakpoints();
  std::vector<u32> Breakpoints();

  void ObserveInstruction(Core::System& system, u32 address);
  void ObserveMemory(Core::System& system, u32 address, u64 value, u32 size, u32 pc,
                     u32 link_register, bool write);
  void ObserveFrame(Core::System& system);
  void ObservePresent(Core::System& system, u64 present_ordinal, u64 frame_number, u32 xfb_address,
                      u32 xfb_width, u32 xfb_stride, u32 xfb_height, u64 resource_id,
                      u64 resource_hash, u64 resource_base_hash, u32 resource_content_ordinal,
                      bool duplicate_xfb, std::string render_source,
                      bool pixel_hash_valid, std::array<u8, 32> pixel_sha256,
                      u32 pixel_width, u32 pixel_height, u32 pixel_stride, u32 pixel_format);
  u64 ObserveGXCommand(Core::System& system, std::span<const u8> command);
  void ObserveGXDraw(Core::System& system, u64 gx_command_ordinal,
                     std::span<const u8> command, u32 primitive, u32 vat, u32 vertex_size,
                     u32 vertex_count, std::span<const u8> gx_state_payload);
  void ObserveEFBCopy(Core::System& system, const LuaDebuggerEfbCopyInfo& info);
  void ObserveEffectivePipeline(Core::System& system,
                                LuaDebuggerEffectivePipelineInfo info);

private:
  LuaDebuggerService() = default;
  bool Enqueue(Core::System& system, LuaDebuggerEvent event);
  static void CapturePresentationSnapshot(Core::System& system, LuaDebuggerEvent* event);
  std::vector<std::pair<u32, u32>> MemoryObserverRanges() const;

  // Serializes lifecycle and debugger commands that temporarily release m_mutex while calling
  // into the CPU/FIFO synchronization layer or the script thread. Hook producers never take this
  // mutex, so they cannot invert the CPU-thread lock order.
  mutable std::mutex m_operation_mutex;
  mutable std::mutex m_mutex;
  Core::System* m_system = nullptr;
  std::unique_ptr<LuaDebuggerSession> m_session;
  std::unique_ptr<LuaDebuggerController> m_controller;
  std::unique_ptr<LuaDebuggerRuntime> m_runtime;
  u64 m_source_ordinal = 0;
  std::vector<std::string> m_hook_errors;
  bool m_hook_failure_latched = false;
  std::atomic<bool> m_active{false};
  std::atomic<u64> m_video_frame_ordinal{0};
  std::atomic<u64> m_gx_command_ordinal{0};
  std::atomic<u64> m_gx_draw_ordinal{0};
  std::atomic<u64> m_gx_frame_draw_ordinal{0};
  std::set<std::array<u8, 32>> m_effective_pipeline_definitions;
  bool m_forced_interpreter = false;
};
}  // namespace SoAL
