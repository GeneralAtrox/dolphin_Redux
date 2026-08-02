Below is the complete Dolphin Redux addition set, excluding all standard Dolphin emulation functionality.

## Embedded Lua debugger

- Dynamically loads a specified 64-bit Lua 5.4 runtime.
- Loads observer scripts without recompiling Dolphin.
- Reloads scripts while the game is running.
- Provides a live Lua console.
- Executes all callbacks on one ordered script thread.
- Supports structured JSON output and a separate error stream.
- Identifies the exact Lua runtime and script with SHA-256 hashes.

## Runtime callbacks

Lua scripts can register and unregister callbacks for:

- PowerPC instruction execution.
- Video-frame completion.
- Memory reads over selected address ranges.
- Memory writes over selected address ranges.
- Complete GX commands.
- GX draw submissions.
- EFB copies, including XFB copies.
- Effective Direct3D 11 pipeline submissions.
- Presented frames.

## CPU and memory evidence

Instruction events provide:

- Exact PowerPC address.
- Program counter.
- Link register.
- Emulated timestamp.
- Global source ordinal.

Memory events provide:

- Address.
- Value.
- Access size.
- Read or write classification.
- Exact writer/reader PC.
- Exact LR.
- Interpreter and JIT-path observation.

Lua can read:

- Unsigned 8-, 16- and 32-bit memory.
- Signed 8-, 16- and 32-bit memory.
- 32- and 64-bit floating-point memory.
- Registers `r0`–`r31`.
- `PC`, `NPC`, `LR`, `CTR`, `CR`, `XER`, `MSR`, and `FPSCR`.
- Symbol addresses from Dolphin’s loaded symbol database.

## GX command and draw evidence

GX command records include:

- Global command ordinal.
- Complete lossless command payload, up to the bounded payload limit.
- Leading command bytes in directly accessible form.
- Deterministic emulated timing.

GX draw records include:

- Command and draw ordinals.
- Draw ordinal within the current frame.
- Primitive type.
- VAT selection.
- Vertex size.
- Vertex count.
- Complete vertex/command payload.
- Canonical active CP state.
- Canonical active BP state.
- Relevant XF state.
- SHA-256 identity of the complete GX state payload.

## Effective graphics-pipeline evidence

For Direct3D 11 draws, it records:

- Indexed or non-indexed draw type.
- Draw base.
- Draw count.
- Base vertex.
- Effective backend pipeline configuration.
- Generated shader source.
- Compiled shader bytecode.
- Vertex and pixel constant-buffer bytes.
- Bound texture descriptors.
- Bound sampler state.
- Bound framebuffer information.
- Resource bindings used by the draw.
- Separate SHA-256 identities for pipeline definitions and per-draw bindings.
- Deduplication of repeated pipeline definitions while retaining their identities.

## EFB/XFB copy evidence

Copy records include:

- GX/frame ordering.
- Destination guest address.
- Destination stride and dimensions.
- Source EFB rectangle.
- Vertical filter coefficients.
- Gamma configuration.
- Y-scale.
- Copy flags.
- Color or depth classification.
- VRAM, RAM and XFB destination classification.
- Texture-cache resource ID.
- Resource hash and base hash.
- Resource content ordinal.
- Optional canonical EFB-source and copy-result pixel hashes.
- Captured pixel dimensions, stride and format.

## Presented-frame evidence

Present records include:

- Presentation ordinal.
- Guest frame number.
- Video-frame ordinal.
- Selected XFB address, width, height and stride.
- Exact texture-cache resource identity.
- Resource content ordinal.
- Duplicate-presentation state.
- Presentation source.
- Canonical RGBA8 pixel SHA-256 when backend readback is available.
- Pixel dimensions, stride and format.

This links:

`GX draw → EFB/XFB copy → resource identity → presented frame`

## Deterministic ordering

- Uses emulated ticks rather than host wall-clock time.
- Assigns a global source ordinal across CPU and graphics producers.
- Assigns independent frame, command and draw ordinals.
- Preserves repeated presentation frames.
- Captures guest state at the producing checkpoint, avoiding later-state contamination.

## Skies of Arcadia render checkpoints

At relevant callbacks it additionally records:

- Title-state value at `0x80311ae0`.
- Six recovered fade words from `0x80347504` through `0x80347518`.
- Whether those addresses were valid at the checkpoint.

This provides the fade value active when each draw or presentation event was produced.

## Execution control

The control interface supports:

- Pause.
- Resume.
- Single PowerPC instruction step.
- Single video-frame step.
- Add breakpoint.
- Remove breakpoint.
- List breakpoints.
- Clear breakpoints.
- Fail-closed rejection when JIT breakpoint prerequisites were not enabled before boot.

## JIT execution profiling

A bounded profiling run can:

- Clear all previous JIT execution counters at a scene boundary.
- Export only blocks whose run count is greater than zero.
- Report total, profiled, unprofiled and executed block counts.
- Record effective and physical block addresses.
- Record block size and feature flags.
- Record run count and cycles spent.
- Record Dolphin’s associated symbol, if available.
- Preserve every original PowerPC instruction address.
- Preserve the exact original instruction bytes.
- Calculate a SHA-256 identity for every executed block.
- Explicitly report blocks lacking complete byte identity.

## Dynamic branch profiling

A bounded run can:

- Clear previous branch records.
- Start recording at an exact scene boundary.
- Snapshot the profile at an endpoint.
- Stop recording.
- Record branch source and actual destination.
- Record the original PowerPC instruction word.
- Record taken and not-taken outcomes.
- Record hit counts.
- Distinguish virtual and physical address observations.
- Provide deterministic boundary PC and emulated timestamp.

## Ghidra catalog exporter

The included Ghidra script exports:

- Function entry address.
- Ghidra function name.
- Function size.
- Every discontiguous body range.
- Exact bytes for every body range.
- SHA-256 for every body range.
- Thunk classification.
- Known callers and callees.
- Referenced strings.
- Optional minimum and maximum address filtering.

## Ghidra profile joins

The JIT join tool:

- Joins executed blocks to one or more Ghidra functions.
- Handles blocks containing instructions from several functions.
- Verifies runtime instructions against Ghidra bytes.
- Detects stale or mismatched catalogs.
- Reports unresolved blocks explicitly.
- Distinguishes identity-verified, address-only and incomplete-catalog results.
- Hashes all profile and catalog inputs.

The branch join tool:

- Verifies each executed branch instruction against Ghidra.
- Decodes direct, conditional, LR and CTR branches.
- Produces exact dynamic call edges.
- Identifies confirmed function-entry edges.
- Identifies LR-transfer edges.
- Preserves taken and not-taken evidence.
- Refuses mismatched or unresolved evidence by default.
- Hashes all input artifacts.

## Read-only and mutation modes

By default:

- Memory and registers are read-only.
- The session is marked `authoritative_read_only`.
- Writes fail closed.

After explicit mutation acknowledgement, Lua can:

- Write unsigned 8-, 16- and 32-bit memory.
- Write `r0`–`r31`, `PC`, `NPC`, `LR`, `CTR`, and `CR`.

Every accepted mutation records:

- Mutation reason.
- Action sequence.
- Target address or register.
- Value/payload SHA-256.
- Mutation classification.

Mutation permanently marks that session non-authoritative.

## Evidence provenance

Session status records:

- Script filename.
- Script SHA-256.
- Lua runtime SHA-256.
- Evidence state.
- Authoritative eligibility.
- Mutation status.
- Ordered action ledger.
- Script reloads.
- Console evaluations.
- Memory and register writes.
- Runtime failures.

Reloading a script or using the console changes the run to exploratory. Runtime or queue failures invalidate an otherwise authoritative session.

## Sandboxing and bounds

Lua execution is restricted by:

- 16 MiB default Lua allocation limit.
- One-million-instruction default callback budget.
- Bounded output record count.
- Bounded GX payload storage.
- Removal of `io`, `os`, `package`, `debug`, `require`, `load`, `loadfile`, `dofile`, and `collectgarbage`.
- A single serialized callback thread.
- Fail-closed queue and runtime-error handling.

## Agent control interface

The Windows named-pipe client provides:

- Configurable private pipe names.
- Connection and response timeouts.
- Bounded response sizes.
- Strict JSON depth and node-count validation.
- Optional binding to the exact server:
  - process ID;
  - process creation time;
  - executable path;
  - Windows user SID.
- Verification before transmitting request bytes.
- Rejection of partial identity specifications.
- Machine-readable command responses.

