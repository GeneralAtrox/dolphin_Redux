// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerSha256.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace SoAL
{
namespace
{
constexpr std::array<std::uint32_t, 64> ROUND_CONSTANTS = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

std::uint32_t ReadBigEndian(const std::uint8_t* bytes)
{
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | bytes[3];
}

void Transform(const std::uint8_t* block, std::array<std::uint32_t, 8>* state)
{
  std::array<std::uint32_t, 64> words{};
  for (std::size_t index = 0; index < 16; ++index)
    words[index] = ReadBigEndian(block + index * 4);
  for (std::size_t index = 16; index < words.size(); ++index)
  {
    const std::uint32_t s0 = std::rotr(words[index - 15], 7) ^
                             std::rotr(words[index - 15], 18) ^ (words[index - 15] >> 3);
    const std::uint32_t s1 = std::rotr(words[index - 2], 17) ^
                             std::rotr(words[index - 2], 19) ^ (words[index - 2] >> 10);
    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
  }

  std::uint32_t a = (*state)[0];
  std::uint32_t b = (*state)[1];
  std::uint32_t c = (*state)[2];
  std::uint32_t d = (*state)[3];
  std::uint32_t e = (*state)[4];
  std::uint32_t f = (*state)[5];
  std::uint32_t g = (*state)[6];
  std::uint32_t h = (*state)[7];
  for (std::size_t index = 0; index < words.size(); ++index)
  {
    const std::uint32_t sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temporary1 = h + sum1 + choose + ROUND_CONSTANTS[index] + words[index];
    const std::uint32_t sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temporary2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary1;
    d = c;
    c = b;
    b = a;
    a = temporary1 + temporary2;
  }
  (*state)[0] += a;
  (*state)[1] += b;
  (*state)[2] += c;
  (*state)[3] += d;
  (*state)[4] += e;
  (*state)[5] += f;
  (*state)[6] += g;
  (*state)[7] += h;
}
}  // namespace

std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> bytes)
{
  std::array<std::uint32_t, 8> state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::size_t offset = 0;
  while (bytes.size() - offset >= 64)
  {
    Transform(bytes.data() + offset, &state);
    offset += 64;
  }

  std::array<std::uint8_t, 128> tail{};
  const std::size_t remaining = bytes.size() - offset;
  std::ranges::copy(bytes.subspan(offset), tail.begin());
  tail[remaining] = 0x80;
  const std::size_t padded_size = remaining < 56 ? 64 : 128;
  const std::uint64_t bit_length = static_cast<std::uint64_t>(bytes.size()) * 8;
  for (std::size_t index = 0; index < 8; ++index)
    tail[padded_size - 1 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8));
  Transform(tail.data(), &state);
  if (padded_size == 128)
    Transform(tail.data() + 64, &state);

  std::array<std::uint8_t, 32> digest{};
  for (std::size_t word = 0; word < state.size(); ++word)
  {
    for (std::size_t byte = 0; byte < 4; ++byte)
      digest[word * 4 + byte] = static_cast<std::uint8_t>(state[word] >> (24 - byte * 8));
  }
  return digest;
}
}  // namespace SoAL
