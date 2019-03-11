#include <stdint.h>

#define ROUNDS 8
uint32_t f(uint32_t, uint32_t);
uint64_t encrypt(uint32_t, uint32_t, uint32_t, uint32_t[]);
uint64_t decrypt(uint32_t, uint32_t, uint32_t, uint32_t[]);
