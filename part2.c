/* This is a code to generate an timing attack on a cache */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "feistel.h"
#include "mersenne.h"
#include "cache.h"

#define LINE_SIZE 64
#define MODE 0
#define REPL 0

//Physical addresses in modern processors are limited to 48 bits --> 256TB of RAM (Max)
#define PHYSICAL_ADDR 48

// Sample 5 different points on the cumulative distribution
#define INTERVALS 5 
#define START_FREQ 4000
#define END_FREQ 9000


/* We perform 10000 iterations to generate a probability curve
 The code is split in 4 steps
 1. Generate Addresses
 2. Pass them through a Feistel Network
 3. Use the encrypted address to index into the Cache
 4. See if a set overflows */
int main(int argc, char *argv[]) {
    /* ---------- We read the parameters for our cache and simulation options ---------- */
    
    if(argc < 4) {
        fprintf(stderr,"Usage: ./simPart2 CacheSizeMB SetAssociativity Part1ProfileCSV APLR\n");
        return EXIT_FAILURE;
    }
    unsigned int cache_size_MB = atoi(argv[1]);
    unsigned int cache_size = atoi(argv[1]) * (1 << 20);
    unsigned int set_associativity = atoi(argv[2]);
    unsigned int num_lines = cache_size / LINE_SIZE;
    unsigned int num_sets = num_lines / set_associativity;
    unsigned int max_trials = 100;
    unsigned int max_addresses = 0;
    unsigned int APLR = 0;

    if(argc == 5)
        APLR = atoi(argv[4]);

    FILE *infile = fopen(argv[3],"r+");
    if(!infile) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    printf("Cache Size: %d bytes\n", cache_size);
    printf("Set Associativity: %d-way\n", set_associativity);
    printf("Number of Cache Lines: %d lines\n", num_lines);
    printf("Number of Sets: %d sets\n", num_sets);
    printf("Number of Trials: %d trials\n", max_trials);
    printf("Accesses Per Line Remapping: %d accesses\n", APLR);
    
    uint64_t *results = (uint64_t*) calloc(sizeof(uint64_t), max_trials * INTERVALS);
    uint32_t* keys = (uint32_t *)calloc(8,sizeof(uint32_t));
    
    /* --------------------- Setup the cache ------------------------- */
    MCache *L3Cache = (MCache*) calloc(1, sizeof(MCache));
    init_cache(L3Cache, num_sets, set_associativity, REPL, LINE_SIZE ,MODE);
    
    char line[16];
    int interval = 0;
    
    // Iterate through the results of part 1 simulations
    while (fgets (line, sizeof(line), infile ) != NULL){
        if(interval >= INTERVALS)
            break;
        if(atoi(line) > START_FREQ + interval * ((END_FREQ-START_FREQ)/INTERVALS)){
            /* ----------------------------Start the trials ------------------------------------ */
            uint64_t address;
            uint64_t encrypted_address = 0, decrypted_address = 0;
            uint32_t left_addr, right_addr;
            MCache_Entry victim;
            bool L3Hit = false;
            for(unsigned int trial_num = 0; trial_num < max_trials; trial_num++){
                invalidate_cache(L3Cache);
                seedMT(trial_num);
                /* ------------- Generate 8 keys for Feistel Network, take from a random number generator ------------- */
                for(int round = 0; round < ROUNDS; round++)
                {
                    /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
                    keys[round] = randomMT();
                    /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
                    keys[round] = keys[round] & 0xFFFFFF; // extracted lower 24 bits
                }


                // Access an array in sequence
                for(address = 0; address <= max_addresses; address++){
                    /* -------------  Step 1. Generate Addresses -------------  */
                    address = address & 0xFFFFFFFFFFFF; //Ensure that the address is 48 bits long (Physical address limit)

                    /* -------------  Step 2. Pass these addresses through a Feistel Cipher -------------  */
                    left_addr = (uint32_t)((address & 0xFFFFFF000000) >> 24);
                    right_addr = (uint32_t)(address & 0x000000FFFFFF);
                    encrypted_address = encrypt(left_addr, right_addr, ROUNDS, keys);

                    // The code commented is for purpose of testing only //

                    /* left_addr = (uint32_t)((encrypted_address & 0xFFFFFF000000) >> 24);
                       right_addr = (uint32_t)(encrypted_address & 0x000000FFFFFF);
                       decrypted_address = decrypt(left_addr, right_addr, ROUNDS, keys);
                       printf("Address: %llx \t | Enc_Address: %llx \t | Dec_Address: %llx\n",address, encrypted_address, decrypted_address); */

                    /* -------------  Step 3. Access the cache with Encrypted Address -------------  */
                    L3Hit = isHit(L3Cache, encrypted_address, false, MODE);
                    if(!L3Hit){
                        victim=install(L3Cache, encrypted_address, 0,true, MODE, LINE_SIZE);
                        /* -------------  Step 4. This set overflows -------------  */
                        if(victim.valid){
                            results[interval*max_trials+trial_num]++;
                        }
                    }
                }
            }
            interval++;
        printf("Finished testing how many misses are generated by %d accesses\n", max_addresses);
        fflush(stdout);
        }
        max_addresses++;
    }


    /* ------------------------  End the trials and write output to files  --------------------- */
    FILE *outfile;
    char *outName = (char*) calloc(256,sizeof(char));
    sprintf(outName, "part2_%d_%d.csv",cache_size_MB,set_associativity);
    printf("Part 2 profiling for a %d MB, %d-way cache complete\n", cache_size_MB, set_associativity);
    outfile = fopen(outName,"w");
    if(!outfile) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    for(uint64_t j = 0; j < INTERVALS; j++){
        for(uint64_t i = 0; i < max_trials; i++){
            fprintf(outfile, "%u,", results[j*max_trials+i]);
        }
        fprintf(outfile, "\n");
    }
    fclose(outfile);
    fclose(infile);

    return 0;
}
