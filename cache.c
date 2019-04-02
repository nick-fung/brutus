//
// Created by Seokin Hong on 3/29/18.
//

#include "cache.h"
#include "math.h"
#include "stdlib.h"
#include "assert.h"
#include "stdio.h"
#include <string.h>
#include "feistel.h"
#include "mersenne.h"


void init_cache(MCache* c, uns sets, uns assocs, uns repl_policy, uns linesize, uns APLR)
{

    c->sets    = sets;
    c->assocs  = assocs;

    c->linesize = linesize;
    c->lineoffset=log2(linesize);
    c->repl_policy = (MCache_ReplPolicy)repl_policy;
    c->index_policy = 0;
    c->entries  = (MCache_Entry *) calloc (sets * assocs, sizeof(MCache_Entry));
    c->fifo_ptr  = (uns *) calloc (sets, sizeof(uns));

    //for drrip or dip
    mcache_select_leader_sets(c,sets);
    c->psel=(MCACHE_PSEL_MAX+1)/2;

    // for CEASER
    c->EpochID = 0;
    c->SPtr = 0;
    c->ACtr = 0;
    c->APLR = APLR;

    // Creates the round keys for the Feistel networks (one for each current and next epoch)
    c->curr_keys = (uint32_t *) calloc(FEISTEL_ROUNDS, sizeof(uint32_t));
    seedMT(0);
    for(int round = 0; round < FEISTEL_ROUNDS; round++){
        /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
        c->curr_keys[round] = randomMT()& 0xFFFFFF;
        /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
        c->curr_keys[round] = 0xFFFFFF; // extracted lower 24 bits
    }
    // If dynamically remapping
    if(APLR){
        c->next_keys = (uint32_t *) calloc(FEISTEL_ROUNDS, sizeof(uint32_t));
        seedMT(1);
        for(int round = 0; round < FEISTEL_ROUNDS; round++){
            c->next_keys[round] = randomMT() & 0xFFFFFF;
        }
    }


}

void invalidate_cache(MCache* c)
{
    for(unsigned long long int i = 0; i < (c->sets * c->assocs); i++)
    {
        c->entries[i].valid=false;
        c->entries[i].NextKey=false;
    }

    c->SPtr = 0;
    c->ACtr = 0;
    c->EpochID += 2;
    seedMT(c->EpochID);
    for(int round = 0; round < FEISTEL_ROUNDS; round++){
        /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
        c->curr_keys[round] = randomMT() & 0xFFFFFF;
    }
    if(c->APLR){
        seedMT(c->EpochID+1);
        for(int round = 0; round < FEISTEL_ROUNDS; round++){
            c->next_keys[round] = randomMT() & 0xFFFFFF;
        }
    }
}

bool isHit(MCache *cache, Addr addr, Flag is_write)
{
    bool isHit=false;
    Addr tag = addr; 

    isHit=mcache_access(cache,tag,is_write); 

    if(is_write)
        cache->s_write++;
    else
        cache->s_read++;


    return isHit;
}

MCache_Entry install(MCache *cache, Addr addr, Addr pc, Flag is_write)
{
    Addr tag = addr;
    MCache_Entry victim;

    victim = mcache_install(cache,tag,pc,is_write);

    return victim;
}

void mcache_select_leader_sets(MCache *c, uns sets)
{
    uns done=0;

    c->is_leader_p0  = (Flag *) calloc (sets, sizeof(Flag));
    c->is_leader_p1  = (Flag *) calloc (sets, sizeof(Flag));

    while(done <= MCACHE_LEADER_SETS){
        uns randval=rand()%sets;
        if( (c->is_leader_p0[randval]==FALSE)&&(c->is_leader_p1[randval]==FALSE)){
            c->is_leader_p0[randval]=TRUE;
            done++;
        }
    }

    done=0;
    while(done <= MCACHE_LEADER_SETS){
        uns randval=rand()%sets;
        if( (c->is_leader_p0[randval]==FALSE)&&(c->is_leader_p1[randval]==FALSE)){
            c->is_leader_p1[randval]=TRUE;
            done++;
        }
    }
}

bool mcache_access(MCache *c, Addr addr, Flag dirty)
{

    uns   set;
    uns   start;
    uns   end;
    uns   ii;
    Addr tag;

    // Encryption/decryption
    uint32_t left_addr;
    uint32_t right_addr;
    // CEASER only
    Flag NextKey = 0;


    // If using CEASER
    if(c->APLR){
        // If we reached APLR accesses, we remap a set
        c->ACtr++;
        if(c->ACtr >= c->APLR){
            set = c->SPtr;
            start = set * c->assocs;
            end = start + c-> assocs;
            for (ii=start; ii<end; ii++){
                MCache_Entry *entry = &c->entries[ii];
                if(entry->valid && !(entry->NextKey))
                {
                    entry->valid = false;
                    tag = entry->tag;
                    left_addr = (uint32_t)((tag & 0xFFFFFF000000) >> 24);
                    right_addr = (uint32_t)(tag & 0x000000FFFFFF);
                    tag = decrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
                    mcache_install(c, tag, 0, (Flag) (entry->dirty | NEXTKEY_MASK));
                }
            }
            // Update set pointer and reset access counter
            c->ACtr = 0;
            c->SPtr++;
            if(c->SPtr >= c->sets){
                c->SPtr = 0;
                c->EpochID++;
                // Swap pointers and recreate new keys
                uint32_t *tmp = c->curr_keys;
                c->curr_keys = c->next_keys;
                c->next_keys = tmp;
                seedMT(c->EpochID+1);
                for(int round = 0; round < FEISTEL_ROUNDS; round++){
                    c->next_keys[round] = randomMT() & 0xFFFFFF;
                }
                // Need to reset all NextKey bits to 0
                for(unsigned long long int i = 0; i < (c->sets * c->assocs); i++)
                {
                    c->entries[i].NextKey=false;
                }
            }
        }
    }


    // Split address into two 24 bits for encryption
    left_addr = (uint32_t)((addr & 0xFFFFFF000000) >> 24);
    right_addr = (uint32_t)(addr & 0x000000FFFFFF);
    tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
    set  = mcache_get_index(c,tag);

    // If we are using CEASER
    if(c->APLR && set < c->SPtr){
        tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->next_keys);
        NextKey = 1;
        set = mcache_get_index(c, tag);
    }

    start = set * c->assocs;
    end   = start + c->assocs;

    c->s_count++;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag) && (entry->NextKey == NextKey))
        {
            entry->last_access  = c->s_count;
            entry->ripctr       = MCACHE_SRRIP_MAX;
            c->touched_wayid = (ii-start);
            c->touched_setid = set;
            c->touched_lineid = ii;
            if(dirty==TRUE) //If the operation is a WB then mark it as dirty
            {
                mcache_mark_dirty(c,tag);
            }
            return true;
        }
    }

    //even on a miss, we need to know which set was accessed
    c->touched_wayid = 0;
    c->touched_setid = set;
    c->touched_lineid = start;

    c->s_miss++;
    return false;
}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

Flag mcache_probe    (MCache *c, Addr addr)
{
    uns64 offset = c->lineoffset;
    Addr  tag  = addr>>offset; // full tags
    uns   set  = mcache_get_index(c,tag);
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag))
        {
            return TRUE;
        }
    }

    return FALSE;
}




////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

Flag mcache_invalidate    (MCache *c, Addr addr)
{
    uns64 offset = c->lineoffset;
    Addr  tag  = addr>>offset; // full tags
    uns   set  = mcache_get_index(c,tag);
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag))
        {
            entry->valid = FALSE;
            entry->NextKey = 0;
            return TRUE;
        }
    }

    return FALSE;
}


////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

void mcache_swap_lines(MCache *c, uns set, uns way_ii, uns way_jj)
{
    uns   start = set * c->assocs;
    uns   loc_ii   = start + way_ii;
    uns   loc_jj   = start + way_jj;

    MCache_Entry tmp = c->entries[loc_ii];
    c->entries[loc_ii] = c->entries[loc_jj];
    c->entries[loc_jj] = tmp;

}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

Flag mcache_mark_dirty    (MCache *c, Addr tag)
{
    //uns64 offset = c->lineoffset;
    uns   set  = mcache_get_index(c,tag);
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag))
        {
            entry->dirty = TRUE;
            return TRUE;
        }
    }

    return FALSE;
}


////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

MCache_Entry mcache_install(MCache *c, Addr addr, Addr pc, Flag dirty)
{
    uns64 offset = c->lineoffset;
    Addr  tag  = addr; // full tags
    uns   set  = mcache_get_index(c,tag);
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii, victim;

    Flag update_lrubits=TRUE;

    MCache_Entry *entry;
    MCache_Entry evicted_entry;

    // Split address into two 24 bits for encryption
    uint32_t left_addr = (uint32_t)((addr & 0xFFFFFF000000) >> 24);
    uint32_t right_addr = (uint32_t)(addr & 0x000000FFFFFF);
    tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
    set  = mcache_get_index(c,tag);
    Flag NextKey = 0;

    // If we are using CEASER check if address indexes into curr epoch sets
    if(c->APLR && (set < c->SPtr || (dirty & NEXTKEY_MASK))){
        tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->next_keys);
        NextKey = 1;
        set = mcache_get_index(c, tag);
    }

    start = set * c->assocs;
    end   = start + c->assocs;

    for (ii=start; ii<end; ii++){
        entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag) && (entry->NextKey == NextKey)){
            fprintf(stderr,"Installed entry already with addr:%llx present in set:%u\n", addr, set);
            exit(-1);
        }
    }

    // find victim and install entry
    victim = mcache_find_victim(c, set);
    entry = &c->entries[victim];
    evicted_entry =c->entries[victim];
    if(entry->valid){
        c->s_evict++;

        if(entry->dirty)
            c->s_writeback++;
    }

    //udpate DRRIP info and select value of ripctr
    uns ripctr_val=MCACHE_SRRIP_INIT;

    if(c->repl_policy==REPL_DRRIP){
        ripctr_val=mcache_drrip_get_ripctrval(c,set);
    }

    if(c->repl_policy==REPL_DIP){
        update_lrubits=mcache_dip_check_lru_update(c,set);
    }


    // Put new information in
    if(dirty & NEXTKEY_MASK){
        entry->NextKey = 1;
        dirty ^= NEXTKEY_MASK;
    }

    entry->tag   = tag;
    entry->valid = TRUE;
    entry->pc    = pc;
    if(dirty==TRUE)
        entry->dirty=TRUE;
    else
        entry->dirty = FALSE;
    entry->ripctr  = ripctr_val;

    if(update_lrubits){
        entry->last_access  = c->s_count;
    }

    c->fifo_ptr[set] = (c->fifo_ptr[set]+1)%c->assocs; // fifo update

    c->touched_lineid=victim;
    c->touched_setid=set;
    c->touched_wayid=victim-(set*c->assocs);

    tag = evicted_entry.tag;
    left_addr = (uint32_t)((addr & 0xFFFFFF000000) >> 24);
    right_addr = (uint32_t)(addr & 0x000000FFFFFF);
    if(!evicted_entry.NextKey)
        tag = decrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
    else
        tag = decrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->next_keys);
    evicted_entry.tag = tag;


    return evicted_entry;
}




////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
Flag mcache_dip_check_lru_update(MCache *c, uns set){
    Flag update_lru=TRUE;

    if(c->is_leader_p0[set]){
        if(c->psel<MCACHE_PSEL_MAX){
            c->psel++;
        }
        update_lru=FALSE;
        if(rand()%100<5) update_lru=TRUE; // BIP
    }

    if(c->is_leader_p1[set]){
        if(c->psel){
            c->psel--;
        }
        update_lru=1;
    }

    if( (c->is_leader_p0[set]==FALSE)&& (c->is_leader_p1[set]==FALSE)){
        if(c->psel >= (MCACHE_PSEL_MAX+1)/2){
            update_lru=1; // policy 1 wins
        }else{
            update_lru=FALSE; // policy 0 wins
            if(rand()%100<5) update_lru=TRUE; // BIP
        }
    }

    return update_lru;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
uns mcache_drrip_get_ripctrval(MCache *c, uns set){
    uns ripctr_val=MCACHE_SRRIP_INIT;

    if(c->is_leader_p0[set]){
        if(c->psel<MCACHE_PSEL_MAX){
            c->psel++;
        }
        ripctr_val=0;
        if(rand()%100<5) ripctr_val=1; // BIP
    }

    if(c->is_leader_p1[set]){
        if(c->psel){
            c->psel--;
        }
        ripctr_val=1;
    }

    if( (c->is_leader_p0[set]==FALSE)&& (c->is_leader_p1[set]==FALSE)){
        if(c->psel >= (MCACHE_PSEL_MAX+1)/2){
            ripctr_val=1; // policy 1 wins
        }else{
            ripctr_val=0; // policy 0 wins
            if(rand()%100<5) ripctr_val=1; // BIP
        }
    }


    return ripctr_val;
}


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_find_victim (MCache *c, uns set)
{
    int ii;
    int start = set   * c->assocs;
    int end   = start + c->assocs;

    //search for invalid first
    for (ii = start; ii < end; ii++){
        if(!c->entries[ii].valid){
            return ii;
        }
    }


    switch(c->repl_policy){
        case REPL_LRU:
            return mcache_find_victim_lru(c, set);
        case REPL_RND:
            return mcache_find_victim_rnd(c, set);
        case REPL_SRRIP:
            return mcache_find_victim_srrip(c, set);
        case REPL_DRRIP:
            return mcache_find_victim_srrip(c, set);
        case REPL_FIFO:
            return mcache_find_victim_fifo(c, set);
        case REPL_DIP:
            return mcache_find_victim_lru(c, set);
        default:
            assert(0);
    }

    return -1;

}


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_find_victim_lru (MCache *c,  uns set)
{
    uns start = set   * c->assocs;
    uns end   = start + c->assocs;
    uns lowest=start;
    uns ii;


    for (ii = start; ii < end; ii++){
        if (c->entries[ii].last_access < c->entries[lowest].last_access){
            lowest = ii;
        }
    }

    return lowest;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_find_victim_rnd (MCache *c,  uns set)
{
    uns start = set   * c->assocs;
    uns victim = start + rand()%c->assocs;

    return  victim;
}



////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_find_victim_srrip (MCache *c,  uns set)
{
    uns start = set   * c->assocs;
    uns end   = start + c->assocs;
    uns ii;
    uns victim = end; // init to impossible

    while(victim == end){
        for (ii = start; ii < end; ii++){
            if (c->entries[ii].ripctr == 0){
                victim = ii;
                break;
            }
        }

        if(victim == end){
            for (ii = start; ii < end; ii++){
                c->entries[ii].ripctr--;
            }
        }
    }

    return  victim;
}


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_find_victim_fifo (MCache *c,  uns set)
{
    uns start = set   * c->assocs;
    uns retval = start + c->fifo_ptr[set];
    return retval;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

uns mcache_get_index(MCache *c, Addr addr){
    uns retval;

    switch(c->index_policy){
        case 0:
            retval=addr%c->sets;
            break;

        default:
            fprintf(stderr,"unsupported index_policy\n");
            exit(-1);
    }

    return retval;
}

void print_cache_stats(MCache * llcache){
    uns64 totLookups_type = 0, totMisses_type = 0, totHits_type = 0;
    uns64 totLookups = 0, totMisses = 0, totHits = 0;

    printf("==========================================================\n");
    printf("==========            LLC Statistics           ===========\n");
    printf("==========================================================\n");
    printf("Cache Configuration: \n");
    printf("\tCache Size:     %dK\n", (llcache->sets*llcache->assocs*llcache->linesize/1024));
    printf("\tLine Size:      %dB\n", llcache->linesize);
    printf("\tAssociativity:  %d\n", llcache->assocs);
    printf("\tTot # Sets:     %d\n", llcache->sets);
    //printf("\tTot # Threads:  %d\n\n", NUMCORES);
    
    printf("Cache Statistics: \n\n");
    
    totLookups=llcache->s_count;
    totMisses=llcache->s_miss;
    totHits=llcache->s_count-llcache->s_miss;

    if( totLookups ) 
    {
        printf("Overall Cache stat:\n");
        printf("Overall_Accesses: %lld\n", totLookups);
        printf("Overall_Misses:   %lld\n", totMisses);
        printf("Overall_Hits:     %lld\n", totHits);
        printf("Overall_MissRate \t : %5f\n\n", ((double)totMisses/(double)totLookups)*100.0);
    }


}
