#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>

#include <cassert>
#include <chrono>
#include <vector>

#include "Hacl_P256.h"
#include "ecp_secp256r1.h"

std::vector<uint8_t>
hexStringToBytes(std::string s)
{
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < s.length(); i += 2) {
    bytes.push_back(std::stoul(s.substr(i, 2), nullptr, 16));
  }
  return bytes;
}
std::string
bytesToHexString(std::vector<uint8_t> bytes)
{
  std::stringstream s;
  for (auto b : bytes) {
    s << std::setfill('0') << std::setw(2) << std::uppercase << std::hex
      << static_cast<int>(b);
  }
  return s.str();
}

void
bench_hacl_p256(bool test)
{
  using std::chrono::duration;
  using std::chrono::duration_cast;
  using std::chrono::high_resolution_clock;
  using std::chrono::milliseconds;

  size_t iterations = 10000;
  auto group_name = "P256";
  auto p = "62d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac3"
           "33a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf";
  auto secret =
    "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346";

  std::vector<uint8_t> pub_bytes = hexStringToBytes(p);
  std::vector<uint8_t> sec_bytes = hexStringToBytes(secret);
  std::vector<uint8_t> shared_secret(64);

  auto t1 = high_resolution_clock::now();
  for (size_t i = 0; i < iterations; i++) {

    bool b = Hacl_P256_dh_responder(
      shared_secret.data(), pub_bytes.data(), sec_bytes.data());

    if (test) {
      // Testing correctness
      if (b != true) {
        printf("Error in Hacl_P256_dh_responder");
      } else {
        std::string derived_result = bytesToHexString(shared_secret);
        std::cout << "shared secret: " << derived_result << std::endl;
        auto expected =
          "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285";
        std::vector<uint8_t> expected_bytes = hexStringToBytes(expected);
        assert(expected_bytes.size() == 32);
        for (size_t i = 0; i < expected_bytes.size(); i++) {
          assert(expected_bytes[i] == shared_secret.data()[i]);
        }

        printf("HACL* Success\n");
      }
    }
  }
  auto t2 = high_resolution_clock::now();

  duration<double, std::milli> ms_double = t2 - t1;
  std::cout << "HACL P-256 ECDH: " << (iterations * 1000.0) / ms_double.count()
            << " ops/s\n";
}

void
bench_ecckiila_p256(bool test)
{
  using std::chrono::duration;
  using std::chrono::duration_cast;
  using std::chrono::high_resolution_clock;
  using std::chrono::milliseconds;

  size_t iterations = 10000;

  std::vector<uint8_t> public_key = hexStringToBytes(
    "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93"
    "a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf");
  std::vector<uint8_t> plain_public_key(64);
  std::vector<uint8_t> plain_private_key = hexStringToBytes(
    "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");

  std::vector<uint8_t> shared(64);

  auto t1 = high_resolution_clock::now();
  for (size_t i = 0; i < iterations; i++) {

    point_mul_secp256r1(shared.data(),
                        shared.data() + 32,
                        plain_private_key.data(),
                        plain_public_key.data(),
                        plain_public_key.data() + 32);
  }
  auto t2 = high_resolution_clock::now();

  duration<double, std::milli> ms_double = t2 - t1;
  std::cout << "ECCKiila P-256 ECDH: "
            << (iterations * 1000.0) / ms_double.count() << " ops/s\n";
}

int
main(int argc, char const* argv[])
{
  bench_hacl_p256(false);
  bench_ecckiila_p256(false);

  return 0;
}
