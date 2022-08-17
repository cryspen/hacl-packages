#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>

typedef std::vector<uint8_t> bytes;

std::vector<uint8_t>
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  int len = static_cast<int>(hex.length()) / 2;
  std::vector<uint8_t> out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

std::string
bytes_to_hex(const std::vector<uint8_t>& data)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

std::string
array_to_hex(const uint8_t* data, size_t len)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (size_t i = 0; i < len; i++) {
    hex << std::setw(2) << std::setfill('0') << int(data[i]);
  }
  return hex.str();
}

static inline bool
compare_and_print(size_t len, uint8_t* comp, uint8_t* exp)
{
  bool ok = memcmp(exp, comp, len) == 0;
  if (!ok) {
    printf(" ERROR\n");
    printf("   computed: %s\n", array_to_hex(comp, len).c_str());
    printf("   expected: %s\n", array_to_hex(exp, len).c_str());
  }
  return ok;
}

std::vector<bytes>
chunk(bytes data, size_t chunk_size)
{
  std::vector<bytes> out(data.size() / chunk_size);

  auto start = data.begin();
  auto end = data.end();

  while (start != end) {
    auto next =
      std::distance(start, end) >= chunk_size ? start + chunk_size : end;

    out.emplace_back(start, next);
    start = next;
  }

  return out;
}
