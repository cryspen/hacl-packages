#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "Libcrux_Kem_Kyber_Kyber768.h"

int main (int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s N where N is the number of iterations\n", argv[0]);
    exit(1);
  }

  char *end;
  int N = strtol(argv[1], &end, 10);

  // All three of the operations below are slow.

  // First operation: generating a key pair.
  uint8_t randomness64[64] = { 0 };

  uint8_t public_key[KYBER768_PUBLICKEYBYTES];
  uint8_t secret_key[KYBER768_SECRETKEYBYTES];

  for (int i = 0; i < N; ++i)
    Libcrux_Kyber768_GenerateKeyPair(public_key, secret_key, randomness64);

  // Second operation: encapsulation
  uint8_t randomness32[32] = { 0 };

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  for (int i = 0; i < N; ++i)
    Libcrux_Kyber768_Encapsulate(ciphertext, sharedSecret, &public_key, randomness32);

  // Third operation: decapsulation
  for (int i = 0; i < N; ++i)
    Libcrux_Kyber768_Decapsulate(sharedSecret, &ciphertext, &secret_key);

  return 0;
}
