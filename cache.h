//
// Created by Seokin Hong on 3/29/18.
//

#ifndef SRC_CACHE_HPP
#define SRC_CACHE_HPP

#include <stdbool.h>
#include <stdint.h>

#define FALSE 0
#define TRUE  1

#define HIT   1
#define MISS  0

#define MCACHE_SRRIP_MAX  7
#define MCACHE_SRRIP_INIT 1
#define MCACHE_PSEL_MAX    1023
#define MCACHE_LEADER_SETS  32

#define FEISTEL_ROUNDS 8
#define NEXTKEY_MASK 0x10

typedef unsigned uns;
typedef unsigned char uns8;
typedef unsigned short uns16;
typedef unsigned uns32;
typedef unsigned long long uns64;
typedef short int16;
typedef int int32;
typedef int long long int64;
typedef int Generic_Enum;

/* Conventions */
typedef uns32 Binary;
typedef uns8 Flag;
typedef uns64		    Addr;

typedef uns64 Counter;
typedef int64 SCounter;

typedef struct MCache_Entry {
    Flag valid;
    Flag dirty;
    // CEASER
    Flag NextKey;
    Addr tag;
    Addr pc;
    uns ripctr;
    uns64 last_access;
    uns block_valid[4]; //block id used in YACC
    uns block_dirty[4]; //dirty bit for blocks
    uns comp_size; //compressed cache size 
    uns block_cnt;
} MCache_Entry;

typedef enum MCache_ReplPolicy_Enum {
    REPL_LRU = 0,
    REPL_RND = 1,
    REPL_SRRIP = 2,
    REPL_DRRIP = 3,
    REPL_FIFO = 4,
    REPL_DIP = 5,
    NUM_REPL_POLICY = 6
} MCache_ReplPolicy;

typedef struct MCache {
    uns sets;
    uns assocs;
    uns linesize;
    uns64 lineoffset;
    MCache_ReplPolicy repl_policy; //0:LRU  1:RND 2:SRRIP
    uns index_policy; // how to index cache

    Flag *is_leader_p0; // leader SET for D(RR)IP
    Flag *is_leader_p1; // leader SET for D(RR)IP
    uns psel;

    MCache_Entry *entries;
    uns *fifo_ptr; // for fifo replacement (per set)

    uns64 s_count; // number of accesses
    uns64 s_miss; // number of misses
    uns64 s_evict; // number of evictions
    uns64 s_writeback; // number of writeback

    uns64 s_read;
    uns64 s_write;

    int touched_wayid;
    int touched_setid;
    int touched_lineid;

    // CEASER Modifications
    uns EpochID; // Epoch ID - for seed generation
    uns SPtr; // Set-Relocation Pointer
    uns64 ACtr; // Access-Counter
    uns APLR; // Accesses-Per-Line-Remap

    uint32_t *curr_keys;
    uint32_t *next_keys;


} MCache;


void init_cache(MCache* c, uns sets, uns assocs, uns repl, uns block_size, uns APLR, Flag yacc_mode);
void invalidate_cache (MCache* c);
bool isHit(MCache* cache, Addr addr, Flag dirty,Flag yacc_mode);
MCache_Entry install(MCache* cache, Addr addr, Addr pc, Flag dirty, Flag yacc_mode, uns comp_size);

//void setData(uint64_t addr, uint8_t* data, int data_size);
//uint8_t* getData(uint64_t addr);
//void clearData(uint64_t addr);


//uns64 m_offset;
//std::map<uint64_t, uint8_t*> data_array;

MCache_Entry mcache_install(MCache *c, Addr addr, Addr pc, Flag dirty);
MCache_Entry mcache_install_yacc(MCache *c, Addr addr, Addr pc, Flag dirty, uns comp_size);
void mcache_new(MCache* c, uns sets, uns assocs, uns linesize, uns repl);
bool mcache_access(MCache *c, Addr addr, Flag dirty);  //true: hit, false: miss
bool mcache_access_yacc(MCache *c, Addr addr, Flag dirty);  //true: hit, false: miss
Flag mcache_probe(MCache *c, Addr addr);

Flag mcache_invalidate(MCache *c, Addr addr);

Flag mcache_mark_dirty(MCache *c, Addr addr);
Flag mcache_mark_dirty_yacc(MCache *c, Addr addr, Addr set, uns block_id);

uns mcache_get_index(MCache *c, Addr addr);

uns mcache_find_victim(MCache *c, uns set);

uns mcache_find_victim_lru(MCache *c, uns set);

uns mcache_find_victim_rnd(MCache *c, uns set);

uns mcache_find_victim_srrip(MCache *c, uns set);

uns mcache_find_victim_fifo(MCache *c, uns set);

void mcache_swap_lines(MCache *c, uns set, uns way_i, uns way_j);

void mcache_select_leader_sets(MCache *c, uns sets);

uns mcache_drrip_get_ripctrval(MCache *c, uns set);

Flag mcache_dip_check_lru_update(MCache *c, uns set);



#endif //SRC_CACHE_HPP
