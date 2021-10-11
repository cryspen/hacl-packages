#include <gtest/gtest.h>

#include "util.h"

#include "Hacl_Chacha20Poly1305_32.h"
#ifdef HACL_CAN_COMPILE_VEC128
#include "Hacl_Chacha20Poly1305_128.h"
#endif
#ifdef HACL_CAN_COMPILE_VEC256
#include "Hacl_Chacha20Poly1305_256.h"
#endif

#include "chacha20poly1305_vectors.h"

// Function point to multiplex between the different implementations.
typedef void (*test_encrypt)(uint8_t *, uint8_t *, uint32_t, uint8_t *, uint32_t, uint8_t *, uint8_t *, uint8_t *);
typedef uint32_t (*test_decrypt)(uint8_t *, uint8_t *, uint32_t, uint8_t *, uint32_t, uint8_t *, uint8_t *, uint8_t *);

bool print_test(test_encrypt aead_encrypt, test_decrypt aead_decrypt, int in_len, uint8_t *in, uint8_t *key, uint8_t *nonce, int aad_len, uint8_t *aad, uint8_t *exp_mac, uint8_t *exp_cipher)
{
    uint8_t plaintext[in_len];
    memset(plaintext, 0, in_len * sizeof plaintext[0]);
    uint8_t ciphertext[in_len];
    memset(ciphertext, 0, in_len * sizeof ciphertext[0]);
    uint8_t mac[16] = {0};

    (*aead_encrypt)(key, nonce, aad_len, aad, in_len, in, ciphertext, mac);
    printf("Chacha20Poly1305 Result (chacha20):\n");
    bool ok = print_result(in_len, ciphertext, exp_cipher);
    printf("(poly1305):\n");
    ok = ok && print_result(16, mac, exp_mac);

    int res = (*aead_decrypt)(key, nonce, aad_len, aad, in_len, plaintext, exp_cipher, exp_mac);
    if (res != 0)
        printf("AEAD Decrypt (Chacha20/Poly1305) failed \n.");
    ok = ok && (res == 0);
    ok = ok && print_result(in_len, plaintext, in);

    return ok;
}

class Chacha20Poly1305Testing : public ::testing::TestWithParam<chacha20poly1305_test_vector>
{
};

TEST_P(Chacha20Poly1305Testing, TryTestVectors)
{
    const chacha20poly1305_test_vector &vectors(GetParam());
    bool test = print_test(&Hacl_Chacha20Poly1305_32_aead_encrypt, &Hacl_Chacha20Poly1305_32_aead_decrypt, vectors.input_len, vectors.input, &vectors.key[0], &vectors.nonce[0], vectors.aad_len, vectors.aad, &vectors.tag[0], vectors.cipher);
    EXPECT_TRUE(test);

#ifdef HACL_CAN_COMPILE_VEC128
    test = print_test(&Hacl_Chacha20Poly1305_128_aead_encrypt, &Hacl_Chacha20Poly1305_128_aead_decrypt, vectors.input_len, vectors.input, &vectors.key[0], &vectors.nonce[0], vectors.aad_len, vectors.aad, &vectors.tag[0], vectors.cipher);
    EXPECT_TRUE(test);
#endif // HACL_CAN_COMPILE_VEC128

#ifdef HACL_CAN_COMPILE_VEC256
    test = print_test(&Hacl_Chacha20Poly1305_256_aead_encrypt, &Hacl_Chacha20Poly1305_256_aead_decrypt, vectors.input_len, vectors.input, &vectors.key[0], &vectors.nonce[0], vectors.aad_len, vectors.aad, &vectors.tag[0], vectors.cipher);
    EXPECT_TRUE(test);
#endif // HACL_CAN_COMPILE_VEC256
}

INSTANTIATE_TEST_SUITE_P(TestVectors, Chacha20Poly1305Testing,
                         ::testing::ValuesIn(vectors));
