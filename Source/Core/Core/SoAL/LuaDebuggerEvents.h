// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "Common/CommonTypes.h"

namespace SoAL
{
enum class LuaDebuggerEventKind : u8
{
  Instruction,
  Frame,
  MemoryRead,
  MemoryWrite,
  Present,
  GXCommand,
  GXDraw,
  EFBCopy,
  EffectivePipeline,
};

struct LuaDebuggerEvent
{
  static constexpr size_t MAX_GX_PAYLOAD_BYTES = 64 * 1024 * 1024;
  LuaDebuggerEventKind kind = LuaDebuggerEventKind::Instruction;
  // Deterministic values supplied by the emulation checkpoint, never host wall time.
  u64 emulated_ticks = 0;
  u64 source_ordinal = 0;
  u32 address = 0;
  u64 value = 0;
  u32 size = 0;
  u32 auxiliary = 0;
  // Exact CPU context captured by the producer. For memory events auxiliary remains the legacy PC
  // alias; new scripts should use these named fields.
  u32 pc = 0;
  u32 link_register = 0;
  // Exact leading GX command bytes packed big-endian. State-setting CP/BP commands fit entirely;
  // longer commands retain an explicitly sized prefix rather than pretending to be complete.
  u64 gx_prefix = 0;
  u32 gx_prefix_size = 0;
  // Complete lossless command bytes. The queue validates size equality and owns a bounded copy.
  std::vector<u8> gx_payload;
  // Canonical active GX state captured immediately before a primitive is submitted. The payload
  // format is versioned and contains CP, BP and XF words in big-endian order; it is intentionally
  // absent from non-draw events.
  std::vector<u8> gx_state_payload;
  std::array<u8, 32> gx_state_sha256{};
  // The D3D11 submission hook emits two canonical, versioned payloads. The definition contains
  // the effective backend configuration plus shader source and bytecode. The binding payload
  // contains draw-time sampler/texture/framebuffer descriptors and the exact uploaded VS/PS
  // constant-buffer bytes. Repeated uses retain the definition hash but omit duplicate bytes.
  std::vector<u8> effective_pipeline_definition;
  std::array<u8, 32> effective_pipeline_definition_sha256{};
  std::vector<u8> effective_pipeline_bindings;
  std::array<u8, 32> effective_pipeline_bindings_sha256{};
  u32 effective_draw_kind = 0;
  u32 effective_draw_base = 0;
  u32 effective_draw_count = 0;
  u32 effective_base_vertex = 0;
  u64 video_frame_ordinal = 0;
  u64 gx_command_ordinal = 0;
  u64 gx_draw_ordinal = 0;
  u64 gx_frame_draw_ordinal = 0;
  u32 gx_primitive = 0;
  u32 gx_vat = 0;
  u32 gx_vertex_size = 0;
  u32 gx_vertex_count = 0;
  // Event-time guest state. These values are read at the producer checkpoint rather than later on
  // the Lua thread, so an active draw cannot accidentally inherit a newer fade value.
  bool presentation_snapshot_valid = false;
  u32 title_state = 0;
  std::array<u32, 6> fade_words{};
  // EFB-copy resource identity and geometry. Resource identity connects the copy produced by the
  // texture cache to the exact XFB resource later selected by Presenter.
  u64 render_resource_id = 0;
  u64 render_resource_hash = 0;
  u64 render_resource_base_hash = 0;
  u32 render_resource_content_ordinal = 0;
  u32 xfb_address = 0;
  u32 xfb_stride = 0;
  u32 xfb_width = 0;
  u32 xfb_height = 0;
  u32 efb_left = 0;
  u32 efb_top = 0;
  u32 efb_right = 0;
  u32 efb_bottom = 0;
  std::array<u32, 3> copy_filter_coefficients{};
  u32 copy_gamma_bits = 0;
  u32 copy_y_scale_bits = 0;
  u32 copy_parameter_flags = 0;
  u32 render_flags = 0;
  bool raw_pixel_capture_valid = false;
  std::array<u8, 32> efb_source_pixels_sha256{};
  std::array<u8, 32> xfb_copy_pixels_sha256{};
  u32 captured_pixel_width = 0;
  u32 captured_pixel_height = 0;
  u32 captured_pixel_stride = 0;
  u32 captured_pixel_format = 0;
  u64 presented_frame_number = 0;
  bool present_pixel_hash_valid = false;
  std::array<u8, 32> present_pixel_sha256{};
  u32 present_pixel_width = 0;
  u32 present_pixel_height = 0;
  u32 present_pixel_stride = 0;
  u32 present_pixel_format = 0;
  std::string render_source;
};

struct LuaDebuggerAddressFilter
{
  u32 first = 0;
  u32 last = 0;

  bool Contains(u32 address) const { return address >= first && address <= last; }
};

struct LuaDebuggerCallbackRegistration
{
  u64 id = 0;
  LuaDebuggerEventKind kind = LuaDebuggerEventKind::Instruction;
  std::optional<LuaDebuggerAddressFilter> address_filter;
  std::string lua_function;
};

// All Lua callbacks execute on this class's single owned thread. Callers must enqueue events only
// from deterministic emulation checkpoints, with source_ordinal resolving events sharing a tick.
// Source ordinal is the cross-thread total-order authority. Emulated ticks remain exact source-time
// observations but may move backwards when independently scheduled CPU/GPU producers enqueue.
class LuaDebuggerEventQueue final
{
public:
  using Dispatch =
      std::function<void(const LuaDebuggerCallbackRegistration&, const LuaDebuggerEvent&)>;

  explicit LuaDebuggerEventQueue(Dispatch dispatch);
  ~LuaDebuggerEventQueue();

  LuaDebuggerEventQueue(const LuaDebuggerEventQueue&) = delete;
  LuaDebuggerEventQueue& operator=(const LuaDebuggerEventQueue&) = delete;

  bool Start(std::string* error = nullptr);
  void Stop();
  bool Register(LuaDebuggerEventKind kind, std::optional<LuaDebuggerAddressFilter> address_filter,
                std::string lua_function, u64* id, std::string* error = nullptr);
  bool Unregister(u64 id);
  bool Enqueue(LuaDebuggerEvent event, std::string* error = nullptr);
  // Runs host/runtime maintenance on the same thread as callbacks. It is accepted only at an idle
  // checkpoint, so reloads and console commands cannot jump ahead of already queued evidence.
  bool ExecuteSync(std::function<void()> task, std::string* error = nullptr);
  void WaitUntilIdle();

  bool IsScriptThread() const;
  size_t PendingCount() const;
  std::vector<LuaDebuggerCallbackRegistration> Registrations() const;
  bool HasMatchingRegistration(LuaDebuggerEventKind kind, u32 address = 0) const;
  bool HasRegistrationKind(LuaDebuggerEventKind kind) const;

private:
  static bool HasAddress(LuaDebuggerEventKind kind);
  void ThreadMain();

  mutable std::mutex m_mutex;
  std::condition_variable m_ready;
  std::condition_variable m_idle;
  Dispatch m_dispatch;
  std::deque<LuaDebuggerEvent> m_events;
  struct SyncTask
  {
    std::function<void()> function;
    std::promise<void> completion;
  };
  std::deque<std::shared_ptr<SyncTask>> m_tasks;
  std::vector<LuaDebuggerCallbackRegistration> m_registrations;
  std::thread m_thread;
  std::thread::id m_script_thread_id{};
  u64 m_next_registration_id = 1;
  u64 m_last_enqueued_ordinal = 0;
  size_t m_queued_payload_bytes = 0;
  bool m_have_enqueue_key = false;
  bool m_started = false;
  bool m_stopping = false;
  bool m_dispatching = false;
};
}  // namespace SoAL
