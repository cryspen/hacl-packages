/*
 *    Copyright 2023 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "Hacl_Hash_SHA3.h"
#include "Libcrux_Kem_Kyber_Kyber768.h"
#include "util.h"

using namespace std;

class KAT
{
public:
  bytes key_generation_seed;
  bytes sha3_256_hash_of_public_key;
  bytes sha3_256_hash_of_secret_key;
  bytes encapsulation_seed;
  bytes sha3_256_hash_of_ciphertext;
  bytes shared_secret;
};

vector<KAT>
read_kats(string path)
{
  ifstream kat_file(path);
  nlohmann::json kats_raw;
  kat_file >> kats_raw;

  vector<KAT> kats;

  // Read test group
  for (auto& kat_raw : kats_raw.items()) {
    auto kat_raw_value = kat_raw.value();

    kats.push_back(KAT{
      .key_generation_seed = from_hex(kat_raw_value["key_generation_seed"]),
      .sha3_256_hash_of_public_key =
        from_hex(kat_raw_value["sha3_256_hash_of_public_key"]),
      .sha3_256_hash_of_secret_key =
        from_hex(kat_raw_value["sha3_256_hash_of_secret_key"]),
      .encapsulation_seed = from_hex(kat_raw_value["encapsulation_seed"]),
      .sha3_256_hash_of_ciphertext =
        from_hex(kat_raw_value["sha3_256_hash_of_ciphertext"]),
      .shared_secret = from_hex(kat_raw_value["shared_secret"]),
    });
  }

  return kats;
}

TEST(Kyber768Test, ConsistencyTest)
{
  uint8_t randomness[64] = { 0 };
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  std::cerr << "ARE WE HERE? 0.5\n";

  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  std::cerr << "ARE WE HERE? 1\n";

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Encapsulate(
    ciphertext, sharedSecret, &publicKey, randomness);

  std::cerr << "ARE WE HERE? 2\n";

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}

TEST(Kyber768Test, NISTKnownAnswerTest)
{
  auto kats = read_kats("kyber768_nistkats.json");

  uint8_t randomness[64] = { 0 };

  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  for (auto kat : kats) {
    // printf("key gen seed: %s\n", bytes_to_hex(kat.key_generation_seed).c_str());
    Libcrux_Kyber768_GenerateKeyPair(
      publicKey, secretKey, kat.key_generation_seed.data());
    // printf("pk: %s\n",
    //        bytes_to_hex(bytes(publicKey, publicKey +
    //        KYBER768_PUBLICKEYBYTES))
    //          .c_str());
    // printf("sk: %s\n",
    //        bytes_to_hex(bytes(secretKey, secretKey +
    //        KYBER768_SECRETKEYBYTES))
    //          .c_str());
    uint8_t pk_hash[32];
    Hacl_Hash_SHA3_sha3_256(pk_hash, publicKey, KYBER768_PUBLICKEYBYTES);
    // printf("pk hash: %s\n", bytes_to_hex(bytes(pk_hash, pk_hash + 32)).c_str());

    uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
    uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Encapsulate(
      ciphertext, sharedSecret, &publicKey, kat.encapsulation_seed.data());

    uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

    EXPECT_EQ(0,
              memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
    EXPECT_EQ(0,
              memcmp(sharedSecret,
                     kat.shared_secret.data(),
                     KYBER768_SHAREDSECRETBYTES));
  }
}

TEST(Kyber768Test, Kat)
{
  uint8_t randomness[64] = { 0 };
  bytes publicKey = from_hex(
    "a72c2d9c843ee9f8313ecc7f86d6294d59159d9a879a542e260922adf999051cc45200c9ff"
    "db60449c49465979272367c083a7d6267a3ed7a7fd47957c219327f7ca73a4007e1627f00b"
    "11cc80573c15aee6640fb8562dfa6b240ca0ad351ac4ac155b96c14c8ab13dd262cdfd51c4"
    "bb5572fd616553d17bdd430acbea3e95f0b698d66990ab51e5d03783a8b3d278a5720454cf"
    "9695cfdca08485ba099c51cd92a7ea7587c1d15c28e609a81852601b0604010679aa482d51"
    "261ec36e36b8719676217fd74c54786488f4b4969c05a8ba27ca3a77cce73b965923ca554e"
    "422b9b61f4754641608ac16c9b8587a32c1c5dd788f88b36b717a46965635deb67f45b129b"
    "99070909c93eb80b42c2b3f3f70343a7cf37e8520e7bcfc416aca4f18c7981262ba2bfc756"
    "ae03278f0ec66dc2057696824ba6769865a601d7148ef6f54e5af5686aa2906f994ce38a5e"
    "0b938f239007003022c03392df3401b1e4a3a7ebc6161449f73374c8b0140369343d9295fd"
    "f511845c4a46ebaab6ca5492f6800b98c0cc803653a4b1d6e6aaed1932bacc5fefaa818ba5"
    "02859ba5494c5f5402c8536a9c4c1888150617f80098f6b2a99c39bc5dc7cf3b5900a21329"
    "ab59053abaa64ed163e859a8b3b3ca3359b750ccc3e710c7ac43c8191cb5d68870c06391c0"
    "cb8aec72b897ac6be7fbaacc676ed66314c83630e89448c88a1df04aceb23abf2e409ef333"
    "c622289c18a2134e650c45257e47475fa33aa537a5a8f7680214716c50d470e3284963ca64"
    "f54677aec54b5272162bf52bc8142e1d4183fc017454a6b5a496831759064024745978cbd5"
    "1a6cedc8955de4cc6d363670a47466e82be5c23603a17bf22acdb7cc984af08c87e14e2775"
    "3cf587a8ec3447e62c649e887a67c36c9ce98721b697213275646b194f36758673a8ed1128"
    "4455afc7a8529f69c97a3c2d7b8c636c0ba55614b768e624e712930f776169b01715725351"
    "bc74b47395ed52b25a1313c95164814c34c979cbdfab85954662cab485e75087a98cc74bb8"
    "2ca2d1b5bf2803238480638c40e90b43c7460e7aa917f010151fab1169987b372abb59271f"
    "7006c24e60236b84b9ddd600623704254617fb498d89e58b0368bcb2103e79353eb587860c"
    "1422e476162e425bc2381db82c6592737e1dd602864b0167a71ec1f223305c02fe25052af2"
    "b3b5a55a0d7a2022d9a798dc0c5874a98702aaf4054c5d80338a5248b5b7bd09c53b5e2a08"
    "4b047d277a861b1a73bb51488de04ef573c85230a0470b73175c9fa50594f66a5f50b41500"
    "54c93b68186f8b5cbc49316c8548a642b2b36a1d454c7489ac33b2d2ce6668096782a2c1e0"
    "866d21a65e16b585e7af8618bdf3184c1986878508917277b93e10706b1614972b2a94c731"
    "0fe9c708c231a1a8ac8d9314a529a97f469bf64962d820648443099a076d55d4cea824a583"
    "04844f99497c10a25148618a315d72ca857d1b04d575b94f85c01d19bef211bf0aa3362e70"
    "41fd16596d808e867b44c4c00d1cda3418967717f147d0eb21b42aaee74ac35d0b92414b95"
    "8531aadf463ec6305ae5ecaf79174002f26ddecc813bf32672e8529d95a4e730a7ab4a3e8f"
    "8a8af979a665eafd465fc64a0c5f8f3f9003489415899d59a543d8208c54a3166529b5392"
    "2");
  bytes secretKey = from_hex(
    "07638fb69868f3d320e5862bd96933feb311b362093c9b5d50170bced43f1b536d9a204bb1"
    "f22695950ba1f2a9e8eb828b284488760b3fc84faba04275d5628e39c5b2471374283c5032"
    "99c0ab49b66b8bbb56a4186624f919a2ba59bb08d8551880c2befc4f87f25f59ab587a79c3"
    "27d792d54c974a69262ff8a78938289e9a87b688b083e0595fe218b6bb1505941ce2e81a5a"
    "64c5aac60417256985349ee47a52420a5f97477b7236ac76bc70e8288729287ee3e34a3dbc"
    "3683c0b7b10029fc203418537e7466ba6385a8ff301ee12708f82aaa1e380fc7a88f8f205a"
    "b7e88d7e95952a55ba20d09b79a47141d62bf6eb7dd307b08eca13a5bc5f6b68581c6865b2"
    "7bbcddab142f4b2cbff488c8a22705faa98a2b9eea3530c76662335cc7ea3a00777725ebcc"
    "cd2a4636b2d9122ff3ab77123ce0883c1911115e50c9e8a94194e48dd0d09cffb3adcd2c1e"
    "92430903d07adbf00532031575aa7f9e7b5a1f3362dec936d4043c05f2476c07578bc9cbaf"
    "2ab4e382727ad41686a96b2548820bb03b32f11b2811ad62f489e951632aba0d1df89680cc"
    "8a8b53b481d92a68d70b4ea1c3a6a561c0692882b5ca8cc942a8d495afcb06de89498fb935"
    "b775908fe7a03e324d54cc19d4e1aabd3593b38b19ee1388fe492b43127e5a504253786a0d"
    "69ad32601c28e2c88504a5ba599706023a61363e17c6b9bb59bdc697452cd059451983d738"
    "ca3fd034e3f5988854ca05031db09611498988197c6b30d258dfe26265541c89a4b31d6864"
    "e9389b03cb74f7ec4323fb9421a4b9790a26d17b0398a26767350909f84d57b6694df83066"
    "4ca8b3c3c03ed2ae67b89006868a68527ccd666459ab7f056671000c6164d3a7f266a14d97"
    "cbd7004d6c92caca770b844a4fa9b182e7b18ca885082ac5646fcb4a14e1685feb0c9ce337"
    "2ab95365c04fd83084f80a23ff10a05bf15f7fa5acc6c0cb462c33ca524fa6b8bb359043ba"
    "68609eaa2536e81d08463b19653b5435ba946c9addeb202b04b031cc960dcc12e4518d428b"
    "32b257a4fc7313d3a7980d80082e934f9d95c32b0a0191a23604384dd9e079bbbaa266d14c"
    "3f756b9f2133107433a4e83fa7187282a809203a4faf841851833d121ac383843a5e55bc23"
    "81425e16c7db4cc9ab5c1b0d91a47e2b8de0e582c86b6b0d907bb360b97f40ab5d038f6b75"
    "c814b27d9b968d419832bc8c2bee605ef6e5059d33100d90485d378450014221736c07407c"
    "ac260408aa64926619788b8601c2a752d1a6cbf820d7c7a04716203225b3895b9342d147a8"
    "185cfc1bb65ba06b4142339903c0ac4651385b45d98a8b19d28cd6bab088787f7ee1b12461"
    "766b43cbccb96434427d93c065550688f6948ed1b5475a425f1b85209d061c08b56c1cc069"
    "f6c0a7c6f29358cab911087732a649d27c9b98f9a48879387d9b00c25959a71654d6f6a946"
    "164513e47a75d005986c2363c09f6b537eca78b9303a5fa457608a586a653a347db04dfcc1"
    "9175b3a301172536062a658a95277570c8852ca8973f4ae123a334047dd711c8927a634a03"
    "388a527b034bf7a8170fa702c1f7c23ec32d18a2374890be9c787a9409c82d192c4bb705a2"
    "f996ce405da72c2d9c843ee9f8313ecc7f86d6294d59159d9a879a542e260922adf999051c"
    "c45200c9ffdb60449c49465979272367c083a7d6267a3ed7a7fd47957c219327f7ca73a400"
    "7e1627f00b11cc80573c15aee6640fb8562dfa6b240ca0ad351ac4ac155b96c14c8ab13dd2"
    "62cdfd51c4bb5572fd616553d17bdd430acbea3e95f0b698d66990ab51e5d03783a8b3d278"
    "a5720454cf9695cfdca08485ba099c51cd92a7ea7587c1d15c28e609a81852601b06040106"
    "79aa482d51261ec36e36b8719676217fd74c54786488f4b4969c05a8ba27ca3a77cce73b96"
    "5923ca554e422b9b61f4754641608ac16c9b8587a32c1c5dd788f88b36b717a46965635deb"
    "67f45b129b99070909c93eb80b42c2b3f3f70343a7cf37e8520e7bcfc416aca4f18c798126"
    "2ba2bfc756ae03278f0ec66dc2057696824ba6769865a601d7148ef6f54e5af5686aa2906f"
    "994ce38a5e0b938f239007003022c03392df3401b1e4a3a7ebc6161449f73374c8b0140369"
    "343d9295fdf511845c4a46ebaab6ca5492f6800b98c0cc803653a4b1d6e6aaed1932bacc5f"
    "efaa818ba502859ba5494c5f5402c8536a9c4c1888150617f80098f6b2a99c39bc5dc7cf3b"
    "5900a21329ab59053abaa64ed163e859a8b3b3ca3359b750ccc3e710c7ac43c8191cb5d688"
    "70c06391c0cb8aec72b897ac6be7fbaacc676ed66314c83630e89448c88a1df04aceb23abf"
    "2e409ef333c622289c18a2134e650c45257e47475fa33aa537a5a8f7680214716c50d470e3"
    "284963ca64f54677aec54b5272162bf52bc8142e1d4183fc017454a6b5a496831759064024"
    "745978cbd51a6cedc8955de4cc6d363670a47466e82be5c23603a17bf22acdb7cc984af08c"
    "87e14e27753cf587a8ec3447e62c649e887a67c36c9ce98721b697213275646b194f367586"
    "73a8ed11284455afc7a8529f69c97a3c2d7b8c636c0ba55614b768e624e712930f776169b0"
    "1715725351bc74b47395ed52b25a1313c95164814c34c979cbdfab85954662cab485e75087"
    "a98cc74bb82ca2d1b5bf2803238480638c40e90b43c7460e7aa917f010151fab1169987b37"
    "2abb59271f7006c24e60236b84b9ddd600623704254617fb498d89e58b0368bcb2103e7935"
    "3eb587860c1422e476162e425bc2381db82c6592737e1dd602864b0167a71ec1f223305c02"
    "fe25052af2b3b5a55a0d7a2022d9a798dc0c5874a98702aaf4054c5d80338a5248b5b7bd09"
    "c53b5e2a084b047d277a861b1a73bb51488de04ef573c85230a0470b73175c9fa50594f66a"
    "5f50b4150054c93b68186f8b5cbc49316c8548a642b2b36a1d454c7489ac33b2d2ce666809"
    "6782a2c1e0866d21a65e16b585e7af8618bdf3184c1986878508917277b93e10706b161497"
    "2b2a94c7310fe9c708c231a1a8ac8d9314a529a97f469bf64962d820648443099a076d55d4"
    "cea824a58304844f99497c10a25148618a315d72ca857d1b04d575b94f85c01d19bef211bf"
    "0aa3362e7041fd16596d808e867b44c4c00d1cda3418967717f147d0eb21b42aaee74ac35d"
    "0b92414b958531aadf463ec6305ae5ecaf79174002f26ddecc813bf32672e8529d95a4e730"
    "a7ab4a3e8f8a8af979a665eafd465fc64a0c5f8f3f9003489415899d59a543d8208c54a316"
    "6529b53922d4ec143b50f01423b177895edee22bb739f647ecf85f50bc25ef7b5a725dee86"
    "8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f");

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];
  // Libcrux_Kyber768_Encapsulate(
  //   ciphertext, sharedSecret, publicKey.data(), randomness);

  // std::cerr << "ARE WE HERE? 2\n";

  // uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  // Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  // EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}
