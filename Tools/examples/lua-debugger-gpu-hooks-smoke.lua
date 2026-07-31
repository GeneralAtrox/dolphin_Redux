-- SPDX-License-Identifier: GPL-2.0-or-later
local seen = {}

local function bytes_to_hex(bytes)
  return (string.gsub(bytes, ".", function(byte)
    return string.format("%02x", string.byte(byte))
  end))
end

local function emit_once(event)
  if seen[event.kind] then return end
  seen[event.kind] = true
  local payload_fields = ""
  if event.kind == "gx_command" then
    if event.gx_payload_size ~= event.size or #event.gx_payload ~= event.size then
      error("incomplete GX payload")
    end
    payload_fields = string.format(',"payload_size":%u,"payload_hex":"%s"',
      event.gx_payload_size, bytes_to_hex(event.gx_payload))
  end
  soal.emit(event.kind, string.format(
    '{"ticks":%d,"ordinal":%d,"value":%u,"size":%u%s}',
    event.emulated_ticks, event.source_ordinal, event.value, event.size, payload_fields))
end

function observe_frame(event) emit_once(event) end
function observe_present(event) emit_once(event) end
function observe_gx(event) emit_once(event) end

soal.on_frame("observe_frame")
soal.on_present("observe_present")
soal.on_gx_command("observe_gx")
