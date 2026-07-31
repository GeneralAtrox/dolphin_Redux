// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace SoAL
{
std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> bytes);
}  // namespace SoAL
