/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "util.h"

#include "Hacl_Ed25519.h"

static void
Ed25519_Sign(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "53b94cbed7c63839112f544f910227c31162d6c0701b790283219eba9247560a");
  bytes msg = hex_to_bytes(
    "1401e603f155206c4892cd3d7cbc93a4d0d9d2eda706c4f50d279393bc083cde2a07bde74f"
    "9b367dbc065e1a1e69d995402fa5343db0bd49666d3ed4b23c0ab60e39d7f49d93c9caf40d"
    "c86996ebd71c0176924a1e0478c4b97f0711935dbc110d98a3bd642a2883c1112db52ef9b3"
    "84547b0e440e39714a3422597849dbd0d1e1b8be92c5cec6a767d67b0b110f870b8fd8dad9"
    "15378b458da4ecfa385a5bfc77403837fc3e92e5f14cad22c4e15aaebc4a434c02bc10ef44"
    "b7d0cca019947ead831fa9446858e03182ac48682fad2a78890ddd10fdaa3b516ad899643f"
    "b882d34ddf0ac8051453b638bb9e217ebad92acbfbf6a9e4b2b1cd899fde59a20543ce4a5b"
    "37690fcf8c17f5236b2769ba31516a30ad07024dd2fdaf0f1942dff2c42ac121b0693ad83b"
    "a3e290cddf3d24be55622be07645551510cd70ecca0fc86ae6bc6f48ac2688e1fddf0f48a9"
    "4c07c21834422af216babc8968803c09d0fa7ea58daba0d20dabb5a6db175c013e29e911be"
    "ba8087bd4ee55479311340cb7dfb7b7e668f7003c755e2070e1edb399621f11d8a2e4f4dd4"
    "01f23f802872254aa531c1006c6f2403cbd9063f99f3864bf3dc535ae822559ac82b66d3b5"
    "b5a9f52ace7c9a6b40a2a184b7da200c5b86d61ef079767516af00116791aa740618b97e66"
    "9ea78b19e99508d9cac6da9558587ab16094d0bcc8bd76e1b38efda0c10f02f7e46f9ced38"
    "fe8fe334471b4455392a0a367dcd62b5b448303aaab24ceaf547d4bce89700f9b126fb7119"
    "9f15ba5cdfb6025c132aeec6d98c329067575c8089d9a32267e25f022a50c2f5e4cf45fca6"
    "33546e9e010a5e7e2c022eff48ea4253bdcb2663cf87bad1ebce2424353bc40faba6d6daa2"
    "97ec96ac970bd4d1743bd45a269496ae4b94212be1e5541db5d8c0ba0e852e3f0fcfbc6c7e"
    "549ea5ec6bdf0d34de7fcae3fbf35d76149cd3613966ef0f74ce588773bd3ea198a74865df"
    "854b16e90969f733c01230eb470c10e2d069ebeeb3ea81c7ce48ebf5804968a024d81aaff9"
    "148f6c7a6e1c2f66991a07cf98");

  bytes my_signature(64);
  while (state.KeepRunning()) {
    Hacl_Ed25519_sign(my_signature.data(), sk.data(), msg.size(), msg.data());
  }
}

static void
Ed25519_Verify(benchmark::State& state)
{
  bytes sk = hex_to_bytes(
    "53b94cbed7c63839112f544f910227c31162d6c0701b790283219eba9247560a");
  bytes pk(32);
  Hacl_Ed25519_secret_to_public(pk.data(), sk.data());
  bytes msg = hex_to_bytes(
    "1401e603f155206c4892cd3d7cbc93a4d0d9d2eda706c4f50d279393bc083cde2a07bde74f"
    "9b367dbc065e1a1e69d995402fa5343db0bd49666d3ed4b23c0ab60e39d7f49d93c9caf40d"
    "c86996ebd71c0176924a1e0478c4b97f0711935dbc110d98a3bd642a2883c1112db52ef9b3"
    "84547b0e440e39714a3422597849dbd0d1e1b8be92c5cec6a767d67b0b110f870b8fd8dad9"
    "15378b458da4ecfa385a5bfc77403837fc3e92e5f14cad22c4e15aaebc4a434c02bc10ef44"
    "b7d0cca019947ead831fa9446858e03182ac48682fad2a78890ddd10fdaa3b516ad899643f"
    "b882d34ddf0ac8051453b638bb9e217ebad92acbfbf6a9e4b2b1cd899fde59a20543ce4a5b"
    "37690fcf8c17f5236b2769ba31516a30ad07024dd2fdaf0f1942dff2c42ac121b0693ad83b"
    "a3e290cddf3d24be55622be07645551510cd70ecca0fc86ae6bc6f48ac2688e1fddf0f48a9"
    "4c07c21834422af216babc8968803c09d0fa7ea58daba0d20dabb5a6db175c013e29e911be"
    "ba8087bd4ee55479311340cb7dfb7b7e668f7003c755e2070e1edb399621f11d8a2e4f4dd4"
    "01f23f802872254aa531c1006c6f2403cbd9063f99f3864bf3dc535ae822559ac82b66d3b5"
    "b5a9f52ace7c9a6b40a2a184b7da200c5b86d61ef079767516af00116791aa740618b97e66"
    "9ea78b19e99508d9cac6da9558587ab16094d0bcc8bd76e1b38efda0c10f02f7e46f9ced38"
    "fe8fe334471b4455392a0a367dcd62b5b448303aaab24ceaf547d4bce89700f9b126fb7119"
    "9f15ba5cdfb6025c132aeec6d98c329067575c8089d9a32267e25f022a50c2f5e4cf45fca6"
    "33546e9e010a5e7e2c022eff48ea4253bdcb2663cf87bad1ebce2424353bc40faba6d6daa2"
    "97ec96ac970bd4d1743bd45a269496ae4b94212be1e5541db5d8c0ba0e852e3f0fcfbc6c7e"
    "549ea5ec6bdf0d34de7fcae3fbf35d76149cd3613966ef0f74ce588773bd3ea198a74865df"
    "854b16e90969f733c01230eb470c10e2d069ebeeb3ea81c7ce48ebf5804968a024d81aaff9"
    "148f6c7a6e1c2f66991a07cf98");

  bytes sig(64);
  Hacl_Ed25519_sign(sig.data(), sk.data(), msg.size(), msg.data());

  while (state.KeepRunning()) {
    Hacl_Ed25519_verify(pk.data(), msg.size(), msg.data(), sig.data());
  }
}

BENCHMARK(Ed25519_Sign);
BENCHMARK(Ed25519_Verify);
BENCHMARK_MAIN();
