#include <stdint.h>
#include <stdio.h>
#include <vector>

static inline bool
compare_and_print(size_t len, uint8_t* comp, uint8_t* exp)
{
  bool ok = true;
  for (size_t i = 0; i < len; i++) {
    ok = ok & (exp[i] == comp[i]);
  }
  if (ok) {
    // printf("Success!\n");
  } else {
    printf("**FAILED**\n");
    printf("computed:");
    for (size_t i = 0; i < len; i++) {
      printf("%02x", comp[i]);
    }
    printf("\n");
    printf("expected:");
    for (size_t i = 0; i < len; i++) {
      printf("%02x", exp[i]);
    }
    printf("\n");
  }
  return ok;
}

static inline bool
print_result(int in_len, uint8_t* comp, uint8_t* exp)
{
  return compare_and_print(in_len, comp, exp);
}

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
to_hex(const std::vector<uint8_t>& data)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}