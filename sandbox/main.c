#include <stdio.h>

unsigned long long is_setdm(unsigned long long bits, unsigned long long result);
unsigned long long is_setto(unsigned long long bits, unsigned long long result);
unsigned long long is_setif(unsigned long long bits, unsigned long long result);

int main(int argc, char **argv)
{
    unsigned long long r1 = 0, r2 = 0, r3 = 0;
    r1 = is_setdm(0x5, r1);
    r2 = is_setto(0x10, r2);
    r3 = is_setif(0x20, r3);

    printf("%llu %llu %llu\n", r1, r2, r3);
}
