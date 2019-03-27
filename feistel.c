#include <stdio.h>
#include "feistel.h"
#include "mersenne.h"

/* ---- Although we operate on 32 bit values,
 we generate a 24 bit value and thereby stick to a 48 bit physical address ---- */

inline uint32_t f(uint32_t block, uint32_t key) {
	uint32_t seed_init = block;
	uint32_t rand = 0;
	
	//seedMT(seed_init*key);
	seedMT(block*key);
	rand = randomMT();
    return (block^key^(rand & 0xFFFFFF));
    //return (block^key);
}

uint64_t encrypt(uint32_t left, uint32_t right, uint32_t rounds, uint32_t keys[]) {
    uint32_t i;
    uint32_t left1 = 0;
    uint32_t right1 = 0;
    uint64_t encrypted_value = 0;
    
    for(i = 0; i < rounds; i++) {
        left1 = f(left,keys[i]) ^ right;
        right1 = left;
        if(i == (rounds-1)) {
            left = right1;
            right = left1;
        } else {
            left = left1;
            right = right1;
        }
    }
    encrypted_value = left;
    encrypted_value = encrypted_value << 24;
    encrypted_value = encrypted_value | right;
    return encrypted_value;
}

uint64_t decrypt(uint32_t left, uint32_t right, uint32_t rounds, uint32_t keys[]) {
    uint32_t i;
    uint32_t left1 = 0;
    uint32_t right1 = 0;
    uint64_t decrypted_value = 0;

    for(i = 0;i < rounds;i++) {
        left1 = f(left,keys[rounds-i-1]) ^ (right);
        right1 = left;
        if(i == (rounds-1)) {
            left = right1;
            right = left1;
        } else {
            left = left1;
            right = right1;
        }
    }
    decrypted_value = left;
    decrypted_value = decrypted_value << 24;
    decrypted_value = decrypted_value | right;
    return decrypted_value;
}

