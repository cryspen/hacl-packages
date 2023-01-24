#include "util.h"

#include "Hacl_NaCl.h"

#define HACL_NACL_SECRETKEYBYTES 32
#define HACL_NACL_PUBLICKEYBYTES 32
#define HACL_NACL_BEFORENMBYTES 32
#define HACL_NACL_KEYBYTES 32
#define HACL_NACL_NONCEBYTES 24
#define HACL_NACL_MACBYTES 16

using namespace std;

static bytes alice_pk(HACL_NACL_PUBLICKEYBYTES, 0);
static bytes alice_sk(HACL_NACL_SECRETKEYBYTES, 0);
static bytes bob_pk(HACL_NACL_PUBLICKEYBYTES, 0);
static bytes bob_sk(HACL_NACL_SECRETKEYBYTES, 0);
static bytes plaintext(1000, 0x37);
static bytes ciphertext(HACL_NACL_MACBYTES + plaintext.size());
static bytes decrypted(plaintext.size(), 0);
static bytes nonce(HACL_NACL_NONCEBYTES, 0);
static bytes tag(HACL_NACL_MACBYTES, 0);
static bytes k(HACL_NACL_BEFORENMBYTES, 0);
static bytes key(HACL_NACL_KEYBYTES, 0);

static void
HACL_NaCl_oneshot_combined(benchmark::State& state)
{
  crypto_box_keypair_alice(alice_sk.data(), alice_pk.data());
  crypto_box_keypair_bob(bob_sk.data(), bob_pk.data());
  generate_random(nonce.data(), nonce.size());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_box_easy(ciphertext.data(),
                              plaintext.data(),
                              plaintext.size(),
                              nonce.data(),
                              bob_pk.data(),
                              alice_sk.data());

    Hacl_NaCl_crypto_box_open_easy(decrypted.data(),
                                   ciphertext.data(),
                                   ciphertext.size(),
                                   nonce.data(),
                                   alice_pk.data(),
                                   bob_sk.data());
  }
}

BENCHMARK(HACL_NaCl_oneshot_combined)->Setup(DoSetup);

static void
HACL_NaCl_oneshot_detached(benchmark::State& state)
{
  crypto_box_keypair_alice(alice_sk.data(), alice_pk.data());
  crypto_box_keypair_bob(bob_sk.data(), bob_pk.data());
  generate_random(nonce.data(), nonce.size());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_box_detached(ciphertext.data(),
                                  tag.data(),
                                  plaintext.data(),
                                  plaintext.size(),
                                  nonce.data(),
                                  bob_pk.data(),
                                  alice_sk.data());

    Hacl_NaCl_crypto_box_open_detached(decrypted.data(),
                                       ciphertext.data(),
                                       tag.data(),
                                       plaintext.size(),
                                       nonce.data(),
                                       alice_pk.data(),
                                       bob_sk.data());
  }
}

BENCHMARK(HACL_NaCl_oneshot_detached)->Setup(DoSetup);

static void
HACL_NaCl_precomputed_combined(benchmark::State& state)
{
  crypto_box_keypair_alice(alice_sk.data(), alice_pk.data());
  crypto_box_keypair_bob(bob_sk.data(), bob_pk.data());
  generate_random(nonce.data(), nonce.size());

  Hacl_NaCl_crypto_box_beforenm(k.data(), bob_pk.data(), alice_sk.data());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_box_easy_afternm(ciphertext.data(),
                                      plaintext.data(),
                                      plaintext.size(),
                                      nonce.data(),
                                      k.data());

    Hacl_NaCl_crypto_box_open_easy_afternm(decrypted.data(),
                                           ciphertext.data(),
                                           ciphertext.size(),
                                           nonce.data(),
                                           k.data());
  }
}

BENCHMARK(HACL_NaCl_precomputed_combined)->Setup(DoSetup);

static void
HACL_NaCl_precomputed_detached(benchmark::State& state)
{
  crypto_box_keypair_alice(alice_sk.data(), alice_pk.data());
  crypto_box_keypair_bob(bob_sk.data(), bob_pk.data());
  generate_random(nonce.data(), nonce.size());

  Hacl_NaCl_crypto_box_beforenm(k.data(), bob_pk.data(), alice_sk.data());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_box_detached_afternm(ciphertext.data(),
                                          tag.data(),
                                          plaintext.data(),
                                          plaintext.size(),
                                          nonce.data(),
                                          k.data());

    Hacl_NaCl_crypto_box_open_detached_afternm(decrypted.data(),
                                               ciphertext.data(),
                                               tag.data(),
                                               plaintext.size(),
                                               nonce.data(),
                                               k.data());
  }
}

BENCHMARK(HACL_NaCl_precomputed_detached)->Setup(DoSetup);

static void
HACL_NaCl_secret_easy(benchmark::State& state)
{
  generate_random(key.data(), key.size());
  generate_random(nonce.data(), nonce.size());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_secretbox_easy(ciphertext.data(),
                                    plaintext.data(),
                                    plaintext.size(),
                                    nonce.data(),
                                    key.data());

    Hacl_NaCl_crypto_secretbox_open_easy(decrypted.data(),
                                         ciphertext.data(),
                                         ciphertext.size(),
                                         nonce.data(),
                                         key.data());
  }
}

BENCHMARK(HACL_NaCl_secret_easy)->Setup(DoSetup);

static void
HACL_NaCl_secret_detached(benchmark::State& state)
{
  generate_random(key.data(), key.size());
  generate_random(nonce.data(), nonce.size());

  while (state.KeepRunning()) {
    Hacl_NaCl_crypto_secretbox_detached(ciphertext.data(),
                                        tag.data(),
                                        plaintext.data(),
                                        plaintext.size(),
                                        nonce.data(),
                                        key.data());

    Hacl_NaCl_crypto_secretbox_open_detached(decrypted.data(),
                                             ciphertext.data(),
                                             tag.data(),
                                             plaintext.size(),
                                             nonce.data(),
                                             key.data());
  }
}

BENCHMARK(HACL_NaCl_secret_detached)->Setup(DoSetup);

BENCHMARK_MAIN();
