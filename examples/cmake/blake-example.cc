/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */
#include "Hacl_Hash_Blake2.h"

using namespace std;

void print_hex_ln(size_t bytes_len, uint8_t *bytes)
{
    for (int i = 0; i < bytes_len; ++i)
    {
        printf("%02x", bytes[i]);
    }

    printf("\n");
}

int main(int argc, char const *argv[])
{
    // Reserve memory for a 64 byte digest, i.e.,
    // for a BLAKE2B run with full 512-bit output.
    uint32_t output_len = 64;
    uint8_t output[64];

    // The message we want to hash.
    const char *message = "Hello, HACL Packages!";
    uint32_t message_len = strlen(message);

    // BLAKE2B can be used as an HMAC, i.e., with a key.
    // We don't want to use a key here and thus provide a zero-sized key.
    uint32_t key_len = 0;
    uint8_t *key = 0;

    Hacl_Blake2b_32_blake2b(
        output_len, output, message_len, (uint8_t *)message, key_len, key);

    print_hex_ln(output_len, output);

    return 0;
}
