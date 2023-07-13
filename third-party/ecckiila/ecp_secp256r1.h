#include <string>

void point_mul_secp256r1(unsigned char outx[32], unsigned char outy[32],
                        const unsigned char scalar[32],
                        const unsigned char inx[32],
			const unsigned char iny[32]);

void point_mul_two_secp256r1(unsigned char outx[32], unsigned char outy[32],
                            const unsigned char a[32],
                            const unsigned char b[32],
                            const unsigned char inx[32],
                            const unsigned char iny[32]);

void point_mul_g_secp256r1(unsigned char outx[32], unsigned char outy[32],
                          const unsigned char scalar[32]);
