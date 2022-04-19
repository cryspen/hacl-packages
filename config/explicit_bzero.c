#include <string.h>

int main()
{
    unsigned char *block[32] = {0};
    explicit_bzero(block, 32);
    return 0;
}
