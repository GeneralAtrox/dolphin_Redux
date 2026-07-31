-- SPDX-License-Identifier: GPL-2.0-or-later
-- Read-only smoke script for the SoAL Lua debugger. It intentionally performs no reload, console,
-- pause or mutation operation, so a clean-boot run can remain authoritative if all outer evidence
-- gates also pass.
local frames = 0
local presents = 0

function observe_frame(event)
  frames = frames + 1
  if frames <= 8 then
    soal.emit("frame", string.format(
      '{"ordinal":%d,"ticks":%d}', event.source_ordinal, event.emulated_ticks))
  end
end

function observe_present(event)
  presents = presents + 1
  if presents <= 8 then
    soal.emit("present", string.format(
      '{"ordinal":%d,"ticks":%d,"present_count":%d}',
      event.source_ordinal, event.emulated_ticks, event.value))
  end
end

soal.on_frame("observe_frame")
soal.on_present("observe_present")
