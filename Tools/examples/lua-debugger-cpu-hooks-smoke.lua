-- SPDX-License-Identifier: GPL-2.0-or-later
local seen = {}

local function emit_once(event)
  if seen[event.kind] then return end
  seen[event.kind] = true
  soal.emit(event.kind, string.format(
    '{"ticks":%d,"ordinal":%d,"address":%u,"size":%u,"pc":%u}',
    event.emulated_ticks, event.source_ordinal, event.address, event.size, event.auxiliary))
end

function observe_instruction(event) emit_once(event) end
-- This smoke script is used only while Dolphin is paused and single-stepped.
soal.on_instruction(0x80000000, 0x817fffff, "observe_instruction")
