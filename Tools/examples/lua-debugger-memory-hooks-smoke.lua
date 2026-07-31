-- SPDX-License-Identifier: GPL-2.0-or-later
local seen = {}
local read_registration
local write_registration

local function emit_once(event)
  if seen[event.kind] then return end
  seen[event.kind] = true
  if event.kind == "memory_read" then soal.unregister(read_registration) end
  if event.kind == "memory_write" then soal.unregister(write_registration) end
  soal.emit(event.kind, string.format(
    '{"ticks":%d,"ordinal":%d,"address":%u,"value":%u,"size":%u,"pc":%u}',
    event.emulated_ticks, event.source_ordinal, event.address, event.value, event.size,
    event.auxiliary))
end

function observe_memory_read(event) emit_once(event) end
function observe_memory_write(event) emit_once(event) end

-- One-shot callbacks remove their native registrations on the first match, allowing the full guest
-- address space to be probed without retaining a sustained all-memory observer.
read_registration = soal.on_memory_read(0x00000000, 0xffffffff, "observe_memory_read")
write_registration = soal.on_memory_write(0x00000000, 0xffffffff, "observe_memory_write")
