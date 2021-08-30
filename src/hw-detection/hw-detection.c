/*
 * A standalone app to detect hardware features.
 */

#include "hw-detection/cpu-features.h"

int main(int argc, char const *argv[])
{
    detect_cpu_features();
    
    printf("\n\n ========== Evercrypt Available CPU Features ==========\n");
    printf("\tAES-NI \t%s supported\n", aesni_support() ? "   " : "not");
    printf("\tPCLMUL \t%s supported\n", clmul_support() ? "   " : "not");
    printf("\tSHA \t%s supported\n", sha_support() ? "   " : "not");
    printf("\tAVX \t%s supported\n", avx_support() ? "   " : "not");
    printf("\tAVX2 \t%s supported\n", avx2_support() ? "   " : "not");
    printf("\tSSSE3 \t%s supported\n", ssse3_support() ? "   " : "not");
    printf("\tSSE4.1 \t%s supported\n", sse4_1_support() ? "   " : "not");
    printf("\tSSE4.2 \t%s supported\n", sse4_2_support() ? "   " : "not");

    return 0;
}