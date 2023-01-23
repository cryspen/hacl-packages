/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "Hacl_Hash_Base.h"
#include "Hacl_RSAPSS.h"
#include "Hacl_Spec.h"
#include "util.h"

using json = nlohmann::json;

TEST(ApiSuite, ApiTest)
{
  // ANCHOR(EXAMPLE)
  // We want to sign and verify a message.

  // Keys
  uint8_t* e;
  uint32_t eBits;
  uint8_t* d;
  uint32_t dBits;
  uint8_t* mod;
  uint32_t modBits;
  // Note: This is not in HACL*.
  //       You need to bring your own keys.
  generate_rsapss_key(&e, &eBits, &d, &dBits, &mod, &modBits);
  uint64_t* skey =
    Hacl_RSAPSS_new_rsapss_load_skey(modBits, eBits, dBits, mod, e, d);
  uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(modBits, eBits, mod, e);

  // Message
  const char* msg = "Hello, World!";
  size_t msgLen = strlen(msg);

  // Salt
  uint32_t saltLen =
    Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_SHA2_256);
  uint8_t* salt = (uint8_t*)malloc(saltLen);
  generate_random(salt, saltLen);

  // Signature
  uint32_t sgntLen = modBits / 8;
  uint8_t* sgnt = (uint8_t*)malloc(sgntLen);

  // Sign
  bool res_sign = Hacl_RSAPSS_rsapss_sign(Spec_Hash_Definitions_SHA2_256,
                                          modBits,
                                          eBits,
                                          dBits,
                                          skey,
                                          saltLen,
                                          salt,
                                          msgLen,
                                          (uint8_t*)msg,
                                          sgnt);

  if (!res_sign) {
    // Error
  }

  bool res_verify = Hacl_RSAPSS_rsapss_verify(Spec_Hash_Definitions_SHA2_256,
                                              modBits,
                                              eBits,
                                              pkey,
                                              saltLen,
                                              sgntLen,
                                              sgnt,
                                              msgLen,
                                              (uint8_t*)msg);

  if (!res_verify) {
    // Error
  }

  free(sgnt);
  free(salt);
  free(pkey);
  free(skey);
  free(mod);
  free(d);
  free(e);
  // ANCHOR_END(EXAMPLE)

  EXPECT_TRUE(res_sign);
  EXPECT_TRUE(res_verify);
}

typedef struct
{
  uint32_t tcId;
  bytes msg;
  bytes sgnt;
  bool expected;
} Test;

typedef struct
{
  bytes e;
  bytes n;
  uint32_t saltLen;
  Spec_Hash_Definitions_hash_alg a;
  std::vector<Test> tests;
} Group;

void
sign(bytes e,
     bytes d,
     bytes n,
     bytes salt,
     Spec_Hash_Definitions_hash_alg alg,
     bytes msg,
     bytes& sgnt,
     bool* out);

void
verify(bytes e,
       bytes n,
       uint32_t saltLen,
       Spec_Hash_Definitions_hash_alg alg,
       bytes msg,
       bytes sgnt,
       bool* out);

// -----------------------------------------------------------------------------

class RsaPssSignSuite : public ::testing::Test
{};

void
sign(bytes e,
     bytes d,
     bytes n,
     bytes salt,
     Spec_Hash_Definitions_hash_alg alg,
     bytes msg,
     bytes& sgnt,
     bool* out)
{
  uint64_t* skey = Hacl_RSAPSS_new_rsapss_load_skey(
    n.size() * 8, e.size() * 8, d.size() * 8, n.data(), e.data(), d.data());

  bytes sgnt_twin(n.size());

  bool got_twin = Hacl_RSAPSS_rsapss_sign(alg,
                                          n.size() * 8,
                                          e.size() * 8,
                                          d.size() * 8,
                                          skey,
                                          salt.size(),
                                          salt.data(),
                                          msg.size(),
                                          msg.data(),
                                          sgnt_twin.data());
  free(skey);

  bool got = Hacl_RSAPSS_rsapss_skey_sign(alg,
                                          n.size() * 8,
                                          e.size() * 8,
                                          d.size() * 8,
                                          n.data(),
                                          e.data(),
                                          d.data(),
                                          salt.size(),
                                          salt.data(),
                                          msg.size(),
                                          msg.data(),
                                          sgnt.data());

  ASSERT_EQ(got, got_twin) << "`Hacl_RSAPSS_rsapss_sign(...)` deviates from "
                              "`Hacl_RSAPSS_rsapss_skey_sign`.";
  ASSERT_EQ(sgnt, sgnt_twin) << "`Hacl_RSAPSS_rsapss_sign(...)` deviates from "
                                "`Hacl_RSAPSS_rsapss_skey_sign`.";

  *out = got;
}

TEST(RsaPssSignSuite, Group)
{
  // Note: This is a vector with (e, d, n) tuples.
  vector<tuple<bytes, bytes, bytes>> keys{
    // 2048-Bit
    std::make_tuple(
      from_hex("010001"),
      from_hex(
        "4a5fb77973f528ba614c0de9615da4fe34017ebad05ef6deabe37e8b3f17e115c9ff14"
        "7cae83ab63e067e5da7374a64c8562d17ea79d1a6cf5a0f5a76ef7abab1954c2c85ce6"
        "ef65f49fdca939ca79fd339359eb9155fccb5c80111e4f7a1d45baab7d6897d9f677e1"
        "e0f2cb4deddf8874882ab64b015acedbf02087e78dc0d9433decb9a09878534c89a6d0"
        "2cdc60af7eaf75b26e594eead203db8228b6f28a1ba9072f7cf7a560998f2156f3e7aa"
        "5f9d352ccb13d743d2a8a0a20468bc9d8a62de0450353a8630e406503a4b83ff6a2beb"
        "972dd6894b0ed91ecf7b4affbdac9f4f4a63326f9491f48b3b65f81c6ecc8c35656484"
        "34f5202371ce78c5d40829"),
      from_hex(
        "afc4c99740ee5d6688f695f3b722b920c5a04b4b9b77672d78ecf0db9d790e0e7c2c1c"
        "dfc371bdb1e17a7a312472735014ac2d2ca054cd24dcb0476b3aeaabf8eb5dbf558bbb"
        "3f083047803ed585dd57807649d2ecbacad45b20e82d46e95333d5a82bfad78b13813c"
        "513e6ab4735ef3113440b7a6570885cf14f81b794eff821589a21a2696befb0a237be6"
        "cd9faebff20e8c3ea9f3fa2461aa78864b5e56f53a017c6c6abcf0d0414bf15884563a"
        "26d01eadcd591deea12d479cb3d5ef0e296e57518a71214ef5d96643c6b2d638f227ba"
        "ab68e124ca1400cbcd3f877e040dfbdf4fc04c566e8e982d2262da9456aa2095d2df69"
        "1ee129207c3f22eacfc8b3")),
    // 4096-Bit
    std::make_tuple(
      from_hex("010001"),
      from_hex(
        "6d77a14574de2a401f853f912ddb6aa03924fc1f1fb4c65e066ee7d69841f7fd028430"
        "28ea80640b848e27001ad27496ae419e7f252052be5f501e392f7bff7107bc43a763ce"
        "1dfb038fafdd427d5910ae4ee7c2d8b7a2319d3f80f3819e6c1a1ac4bcde79bd33ad9b"
        "2bc02b776a71b31a3af89862bd6e2a51a58d16b4a19992056eb05f9dbbfaac85cb3036"
        "fe5e237bcc20e4a7234a0697fd7260c63a39a1ab23a13a0cde1c38268d45efc34a825a"
        "a76e2765058a83e245571e4ba753d318cd80390817cd0f30d28bde643aeec7fff349e7"
        "c2b8e41965bd2bf73b984576d81c250d82610fd625fec93d6b73558db0de10ea0d7771"
        "17c0dd35f415543077bb27ebd2c7a0b8a1a1954e4fe3d81a764bfa21153b38a9d0525e"
        "5193c8ffd3aee78b39e39d20d1914beb2e1cedc30ee0d41d8d1ca36014d122788e97f9"
        "98b69c96a54b045f562f932ac1fd99ad19a812b3a982ec6743b50bbd40a5727355558f"
        "1e24b414feed1a5f9514ea107d2b28be601c52a2dac9bd67036a98ac4f644a7406e5d0"
        "e67ade679a629feeb10f003610249fd13bd50c5db32a9af17ad711b8abc8fcfc179990"
        "2c00a8a89ee36b3ab36638208f15a86f171ebc3aaf50daa28939de2d40ccdbb91c835c"
        "a4efd18a6e12a9ed40939999176b40b7056183c65bba62494193fe5eef1d9c08ddfd27"
        "5834a7af358734c745420774a9ebf8ce3a9d8c961299"),
      from_hex(
        "ea6d38de07b5a48ddae301c90d76ee96c9fefd731419c83a430be3a347efdfbc3abbd2"
        "2b00abf9e8cccb3cacc5f11f2b7b21397786ef3a09005d22599b0230e95939c1ad29d0"
        "3feb66ac001328c4c77173adc54ec76e22a8b8a5591b2aa304bf5a4ae61eb0490e8536"
        "e537ae37e98610adfada9c4e727e5ccd47df1c36a4dce7a3fd2331e63710284a6a121a"
        "929e2af68d6d7fa0c5291d2b68467418e2ee05b6256dcea56a27afc8c4a72dbe26c72f"
        "5a82810048ac4499e575e33aedfc41857d06c1527f028f472d5ec6f11cd7e145bc12cc"
        "08452fe05c8a5fe29e25efc7e6429d074c4dbf76dc100574b11d3a5f5de16a3f4f9b78"
        "c73de6f1d93acd1ce264787525fd488482693f6911d27d0c888b3f67a8df7232653cc8"
        "cb12932128cd20ef722c5c62619ff817674dec61fa05a2ad7b07079587e6e2cff4b280"
        "9ecb76cf701d5769a15615124c2618f60ce61c4371364928352fdab970e038e33c6741"
        "609f84d197a066a9a182ba3005416745276caf52e0788d888fa93ddf248c22fe879441"
        "9e18e212d420237c00539c31e4138b2444a316285f626df8332d69576b77880be872c1"
        "3c579a54dcc46fe17ce02a2d5225d791d75ff6fa219d8d8de6804eed535daf870325dd"
        "78a185fc16854453b2ebe71db69a8afbf0e9c5def986a285fa06eb0124ed4a5bc8ead9"
        "2b001afbbda9968a07ba28b60420e81169a5454ffb6b")),
    // 8192-Bit
    std::make_tuple(
      from_hex("010001"),
      from_hex(
        "3ea9a466de2903617e201ccabf5bf939efe2309d72fb95e8776bd0415dc79366605e01"
        "be3f4a8fd03c7fddc9ecbc6d9a3bca2a6c75a9e563e807a015c76daa26fdc0c0337fd9"
        "84a4f05c30e82fa91437e4b3f2cddd63273b183dbfc76353f7ecb5bf3490b39afac821"
        "da037c1b06eb5ae7bcf1a910529c9366f7daeb0c478c2749f49453bd1674eab58598c6"
        "5827c70fd2de994a06ca9426bfdaa5bebe23f9ce8c5d875d62d549a66b0f5f203f697a"
        "aa5ede9358972f1662bec72b8c485e103f3be0119da8e8a1fb363c3e3c561b20b2955a"
        "ec4d0b38d73c5e3728c16fc7ca066b7fddd2b46a05338f9b8d88a3a899fa02d125f801"
        "e70335e0f69ec8abb760b51195d72cc959d2abfb76e343c6cee3dbbfd423f91763f40c"
        "0888cab8386ad263f5125239f1f14413ee8b07b3592cc22c21870c80cfe1ec1da306ca"
        "b0736f547117572496b8e26522970aab09b1f265340167b9d2e8a01a7190936e5118ad"
        "9b6f56bbccacfc7708ada0099d20f5d3d23dbfeb5d9e9bf1327607b266ebc656c3b9fe"
        "2ff2957212a237d2a02f9f4f655915d6e4906a5f0d8632fee8302a70d1415bd0a6f8c3"
        "30948a7d9d827ed73f73af7595f2c37bd85226c53e9e8c688fd32d4140d090d4620537"
        "c291d9183e70f824651a0b43f07e138a4baa6578fb9f3a4668dba142d0006a6706392e"
        "7835ddb72606b9c8a0bb2ac974cebf47262138fd5b99c5c3ba10d1c1343e7e5e84be6e"
        "46faa1ef668522dfabadb0e3eb76a19b2a33783092de15f9dba087eb59896eecc34fe4"
        "8e60a9070d5c7c54a60394c9c8b7291c2700706cdb2b225d169fa8209cc2cd2736e5fa"
        "655976cf114473e8ff71b379d03a2221b45704441f80e57c5c2ccc5bee3a20413e8727"
        "413e534d7f07740e30de523076700bffff197487ca700da70d44c8696fa532aa61c620"
        "aae6591b3fca591f0b59ddcfcbeb17a95b2463ef54aaa5f9a7cebc347588eab7dbe2ee"
        "cc14a3d5af07d90d65125b28a77b625ee05925457956b8624f291d7fefc2c3258cdc58"
        "2d34d11e5bd10bac856b3c2a06819200214f2577934cb8b9aa27dd2668ea18f66520bb"
        "d5b6b8efb86397ae5552ae390bf44a4c80217671952c21127b451097961c4a3214487f"
        "a43d727d3c2ce98463514f71e71a1873125df8fd88bab082cedf0a872065c003552dc4"
        "79e9926a6ca6728c96e12a09f5bd7565178efdbe80e36306bf8670d0141503cce2df41"
        "869309f06d65aaca2fb731d20045d18821546a2ff1dc864bd6d18ce3079d8641c93980"
        "62409bf98c7dbca94639da57d03e1afa609b99dbcd176939e67b8c852b7f4546305a03"
        "a5df5efa08bbef0dc7340feb2706bb831b0eb7675ba77fe86e4feff514a2311496cba6"
        "9b84511d5d6229cc93b74e91a7341075b8eb82cfad3d420215b3e38845cee8de0b9c25"
        "116b11b3e99ba7cf29"),
      from_hex(
        "bac9c09e03365908c01828ed1d95657c70336cb9b0b1d5862ccef9d7b08dc9cf2fc468"
        "906513cea9b9291524855f341422fb8801ad7f11b23c72f2dbe016eef017efc49ea2a6"
        "ee4e898ca5f39230cf2d65ed8102c600a8c48a6e562d5a8eca606e0e53525ebae316fd"
        "ffbc71b813a2c725008d491f693f33db26842ad6f96a27852e10e9140791899682cf42"
        "2bb64f205e6f988475e37bd5d97fa85ca2f38a6175dbf29eccd262a482f1846e8d6021"
        "c3e3b1800c6b1e7481721ba567b2ce49ca40f6d19ba8fa5405085a98130d9df20c2228"
        "36adc4205a0b31e6533c93c01eb7fd47585c0ef58420f02180333f19b4883dcb9cb721"
        "bb7454e88e24ed00d0cd1349163f9b08049c777d6fd5d580468bb59dadbefed9fbcd3b"
        "a56bca13ec912922877786dc7d0b8118c9018a31554db3f406d644e2088e19c03a8cc5"
        "18d372c86ae32642b79dbd53f68c1ccec04600e001f0a0890dfa4e6bef14f27500b5d0"
        "66cd5ff53bf97e261c9ad2ee0326875b37d6aa9e180258d102ab48206671a86bfc308d"
        "b43b3692038b082f0a7b76f6f2e50bfe2a3c4d66d0348af2462d88d3669b6310bac858"
        "3a969cefc4c1fd45b9f04aa0cb2a24d31f643e07ef1740c09739edbf60bbff0870a320"
        "6fe4608727d002db62179e2b3807af6dee67157cb7b1d28fd054b2bcb0be557572463e"
        "497fd9074936eee049d1b2e0ffe2cc64c2211ac9957ab77546f240e07df719d3c283bb"
        "97593cb5d8650ccdff1a21f23666afb6e4b2032b4751568477bb65af5a468daf09b717"
        "68e04023ac391e1e2ad326a1c1a507fec7edcc749c8171c9abb155eaff09946883c7d1"
        "d364344406657e93b49c7e02ef6fa0b528704b343f648d11aaea3954c54bb89b1abf50"
        "c5b67074a4cf13788444755e7d2f085920e6ffb2d3989f56be6cb38819ba50def9aef8"
        "84aabce8efa5e008a48adbd6404329fb44fdb946a326ff63692befe9b5817a1064398e"
        "7fb6e7e97b74ee64612ce65a2407bb4ccc42aba2efb707e6db4b64f0539b352618d9d6"
        "6841003ecf8496949f44764b5bb9c2d745a4ec5dabc6c506b9916a045ca1abb1427ee6"
        "accceef061334d733e9b0c81c147e449095ec00975685851d9b07fa4f1279f8a0621c8"
        "8ab5fa325dbdbcc7717e77e71f4208fc607c13f32d2e993a637a624c3e4de8d1e0b8c5"
        "6c80b3b113bf2b07346275dc3d89ddaad32149116812844d0df5a0bc9176b3778e4eef"
        "2d7ef08b127f81fa6f87a7766ac115586750386fb7cc335cc98423f9d7cc96015ba5f2"
        "010346e9e6216bd5a80f45ea6327f2e618008c685fcc4c77e0e6459698d74e9078ed6a"
        "741f66e1aa4d32c7d99a8da0c23f0689cac3f0418c5cee71bbd3b65856ac50ded146ab"
        "d5f305f3d89eb691fd1ae42feddbe67896c88359ecc273a0cf5300ad4c8881e558d0d6"
        "9105f79d4b71468d69"))
  };

  std::vector<bytes> tests{
    from_hex(""),
    from_hex("00"),
    from_hex("aa"),
    from_hex("ff"),
    from_hex("0000000000000000"),
    from_hex("aaaaaaaaaaaaaaaa"),
    from_hex("ffffffffffffffff"),
    from_hex("000000000000000000"),
    from_hex("aaaaaaaaaaaaaaaaaa"),
    from_hex("ffffffffffffffffff"),
  };

  std::vector<Spec_Hash_Definitions_hash_alg> hashes{
    // TODO: #100
    Spec_Hash_Definitions_SHA2_256,
    Spec_Hash_Definitions_SHA2_384,
    Spec_Hash_Definitions_SHA2_512,
  };

  for (auto key : keys) {
    bytes e;
    bytes d;
    bytes n;
    tie(e, d, n) = key;

    for (auto hash_alg : hashes) {
      uint32_t saltLen = Hacl_Hash_Definitions_hash_len(hash_alg);
      bytes salt(saltLen, 'A');

      bytes signature(n.size());

      for (auto test : tests) {
        bool got_sign;
        sign(e, d, n, salt, hash_alg, test, signature, &got_sign);

        bool got_verify;
        verify(e, n, salt.size(), hash_alg, test, signature, &got_verify);

        ASSERT_TRUE(got_verify);
      }
    }
  }
}

// -----------------------------------------------------------------------------

void
verify(bytes e,
       bytes n,
       uint32_t saltLen,
       Spec_Hash_Definitions_hash_alg alg,
       bytes msg,
       bytes sgnt,
       bool* out)
{
  uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(
    n.size() * 8, e.size() * 8, n.data(), e.data());

  bool got1 = Hacl_RSAPSS_rsapss_verify(alg,
                                        n.size() * 8,
                                        e.size() * 8,
                                        pkey,
                                        saltLen,
                                        sgnt.size(),
                                        sgnt.data(),
                                        msg.size(),
                                        msg.data());
  free(pkey);

  bool got2 = Hacl_RSAPSS_rsapss_pkey_verify(alg,
                                             n.size() * 8,
                                             e.size() * 8,
                                             n.data(),
                                             e.data(),
                                             saltLen,
                                             sgnt.size(),
                                             sgnt.data(),
                                             msg.size(),
                                             msg.data());

  ASSERT_EQ(got1, got2) << "`Hacl_RSAPSS_rsapss_verify(...)` deviates from "
                           "`Hacl_RSAPSS_rsapss_pkey_verify(...)`.";

  *out = got2;
}

class RsaPssVerifySuite : public ::testing::TestWithParam<Group>
{};

TEST_P(RsaPssVerifySuite, Group)
{
  auto group = GetParam();

  for (auto test : group.tests) {
    bool got;
    verify(group.e, group.n, group.saltLen, group.a, test.msg, test.sgnt, &got);

    EXPECT_EQ(test.expected, got) << "tcId=" << test.tcId;
  }
}

std::vector<Group>
read_json(char* path)
{
  json tests;
  std::ifstream file(path);
  file >> tests;

  std::vector<Group> testGroups;

  for (auto& group_raw : tests["testGroups"].items()) {
    auto group = group_raw.value();

    bytes e = from_hex(group["e"]);
    bytes n = from_hex(group["n"]);

    // Remove first 0x00 byte in n.
    if (n[0] == 0x00) {
      n.erase(n.begin());
    } else {
      std::ostringstream msg;
      msg << "Expected first byte of \"n\" to be 0x00 in Wycheproof test (path="
          << path << ").";

      throw std::invalid_argument(msg.str());
    }

    uint32_t saltLen = group["sLen"];

    Spec_Hash_Definitions_hash_alg a;
    std::string sha = group["sha"];
    if (sha == "SHA-256") {
      a = Spec_Hash_Definitions_SHA2_256;
    } else if (sha == "SHA-512") {
      a = Spec_Hash_Definitions_SHA2_512;
    } else {
      std::ostringstream msg;
      msg << "Unexpected value \"" << sha
          << "\" in field \"sha\" (path=" << path << ").";

      throw std::invalid_argument(msg.str());
    }

    std::vector<Test> tests;
    for (auto& test_raw : group["tests"].items()) {
      auto test = test_raw.value();
      uint32_t tcId = test["tcId"];

      auto msg = from_hex(test["msg"]);
      auto sgnt = from_hex(test["sig"]);

      bool expected;
      std::string result = test["result"];
      if (result == "valid" || result == "acceptable") {
        expected = true;
      } else if (result == "invalid") {
        expected = false;
      } else {
        std::ostringstream msg;
        msg << "Unexpected value \"" << result
            << "\" in field \"result\" (file=" << path << ", tcId=" << tcId
            << ").";

        throw std::invalid_argument(msg.str());
      }

      tests.push_back(Test{
        .tcId = tcId,
        .msg = msg,
        .sgnt = sgnt,
        .expected = expected,
      });
    }

    testGroups.push_back({
      .e = e,
      .n = n,
      .saltLen = saltLen,
      .a = a,
      .tests = tests,
    });
  }

  return testGroups;
}

INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha256Salt0,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_2048_sha256_mgf1_0_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss2048Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_2048_sha256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss3072Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_3072_sha256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss4096Sha256Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_4096_sha256_mgf1_32_test.json"))));

INSTANTIATE_TEST_SUITE_P(RsaPss4096Sha512Salt32,
                         RsaPssVerifySuite,
                         ::testing::ValuesIn(read_json(const_cast<char*>(
                           "rsa_pss_4096_sha512_mgf1_32_test.json"))));

// -----------------------------------------------------------------------------

TEST(BadSecretKey, RsaPssLoadKey)
{
  // (e, d, n)
  std::vector<std::tuple<bytes, bytes, bytes>> tests{
    { from_hex(""), from_hex(""), from_hex("") },
    { from_hex(""), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex(""), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("") },
    { from_hex("AA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AA"), from_hex("AAAA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AA"), from_hex("AA") },
    { from_hex("AAAA"), from_hex("AAAA"), from_hex("AA") },
  };

  for (auto test : tests) {
    bytes e, d, n;
    std::tie(e, d, n) = test;

    uint64_t* skey = Hacl_RSAPSS_new_rsapss_load_skey(
      n.size() * 8, e.size() * 8, d.size() * 8, n.data(), e.data(), d.data());

    ASSERT_TRUE(skey == NULL);
  }
}

TEST(BadPublicKey, RsaPssLoadKey)
{
  // (e, n)
  std::vector<std::tuple<bytes, bytes>> tests{
    { from_hex(""), from_hex("") },
    { from_hex(""), from_hex("FF") },
    { from_hex("AA"), from_hex("") },
  };

  for (auto test : tests) {
    bytes e, n;
    std::tie(e, n) = test;

    uint64_t* pkey = Hacl_RSAPSS_new_rsapss_load_pkey(
      n.size() * 8, e.size() * 8, n.data(), e.data());

    ASSERT_TRUE(pkey == NULL);
  }
}
