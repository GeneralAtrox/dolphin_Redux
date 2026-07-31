# Dolphin Redux Lua Debugger

Dolphin Redux embeds a read-only-by-default Lua 5.4 debugger for collecting machine-readable
GameCube/Wii runtime evidence. It observes the emulated CPU, memory, FIFO/GX commands, draw state,
EFB/XFB copies, the effective Direct3D 11 pipeline, and presented frames. The debugger is controlled
through a local Windows named pipe. The event system is general-purpose; this fork additionally
records the known Skies of Arcadia Legends title-state and fade words at render checkpoints.

## Build and run

Build Dolphin normally on Windows. The debugger loads Lua dynamically, so provide the path to a
compatible 64-bit Lua 5.4 runtime DLL when starting a script. Start a game in Dolphin, then use a
second PowerShell window:

```powershell
$runtime = 'C:\path\to\lua54.dll'
$script = (Resolve-Path '.\Tools\examples\lua-debugger-frame-smoke.lua').Path
.\Tools\soal-cli.ps1 lua status
.\Tools\soal-cli.ps1 lua start $runtime '|' $script
.\Tools\soal-cli.ps1 lua output
.\Tools\soal-cli.ps1 lua errors
.\Tools\soal-cli.ps1 lua stop
```

The default pipe is `dolphin-redux`. Set `SOAL_PIPE_NAME` before launching Dolphin and pass the same
name with `-PipeName` to select another pipe.

## Control commands

The client supports:

- `lua start <runtime> | <script>`, `lua stop`, `lua status`, `lua reload <script>`
- `lua output`, `lua errors`, `lua console <code>`
- `lua pause`, `lua resume`, `lua step instruction`, `lua step frame`
- `lua breakpoint add <hex>`, `remove <hex>`, `list`, and `clear`
- `lua mutation enable <acknowledgement>`

Mutation is disabled by default. Enabling it marks the session as non-authoritative research mode.
The client can also bind a request to the exact server process identity using its
`-ExpectedServer*` parameters.

## Lua API

Scripts register named global callback functions:

```lua
function observe_write(event)
  soal.emit("write", string.format(
    '{"address":%u,"value":%u,"size":%u,"pc":%u}',
    event.address, event.value, event.size, event.auxiliary))
end

local registration = soal.on_memory_write(0x80000000, 0x817fffff, "observe_write")
```

Available registrations are `on_instruction`, `on_frame`, `on_memory_read`, `on_memory_write`,
`on_gx_command`, `on_gx_draw`, `on_efb_copy`, `on_effective_pipeline`, and `on_present`.
`unregister` removes a registration. `emit` writes structured output for `lua output`.

Read helpers are `read_u8`, `read_u16`, `read_u32`, `read_s8`, `read_s16`, `read_s32`, `read_f32`,
`read_f64`, `read_register`, and `symbol`. Write helpers are unavailable until mutation is
explicitly enabled.

The examples in `Tools/examples/lua-debugger-*.lua` show bounded CPU, memory, GX, frame, and present
observers. Instruction callbacks require the interpreter or explicit pause/single-step operation;
memory callbacks work in both the interpreter and JIT paths.

## Evidence model

Events carry monotonically increasing source ordinals and emulated timing. GX command and draw
events retain complete command payloads and canonical GX state. D3D11 draw events retain shader,
constant, texture, sampler, framebuffer, and backend state. EFB-copy events link copy parameters to
the resulting texture-cache resource. Present events link the selected guest XFB resource to a
SHA-256 of its tightly packed RGBA8 pixels when the backend permits readback.

For Skies of Arcadia Legends, render events also snapshot title state at `0x80311ae0` and the six
fade words at `0x80347504` through `0x80347518`. Those fields are valid only when the mapped guest
addresses exist; other games receive the generic event fields with the presentation snapshot marked
invalid.

Use these records, guest state, and deterministic replay as primary evidence. Screenshots are useful
for orientation and visual confirmation, but are not authoritative evidence for exact timing,
values, or render ownership.

The pipe transport and effective-pipeline capture currently target Windows and Direct3D 11. Other
backends still receive the CPU, memory, GX, EFB-copy, and frame hooks, but do not emit D3D11
effective-pipeline records.
