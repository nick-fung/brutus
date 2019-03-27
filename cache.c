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


void init_cache(MCache* c, uns sets, uns assocs, uns repl_policy, uns linesize, uns APLR, Flag yacc_mode)
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
        c->curr_keys[round] = randomMT();
        /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
        c->curr_keys[round] &= 0xFFFFFF; // extracted lower 24 bits
    }
    c->next_keys = (uint32_t *) calloc(FEISTEL_ROUNDS, sizeof(uint32_t));
    seedMT(1);
    for(int round = 0; round < FEISTEL_ROUNDS; round++){
        /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
        c->next_keys[round] = randomMT();
        /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
        c->next_keys[round] &= 0xFFFFFF; // extracted lower 24 bits
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
    c->EpochID++;
    seedMT(c->EpochID);
    for(int round = 0; round < FEISTEL_ROUNDS; round++){
        /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
        c->curr_keys[round] = randomMT();
        /* as addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
        c->curr_keys[round] &= 0xFFFFFF; // extracted lower 24 bits
    }
    seedMT(c->EpochID+1);
    for(int round = 0; round < FEISTEL_ROUNDS; round++){
        /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
        c->next_keys[round] = randomMT();
        /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
        c->next_keys[round] &= 0xFFFFFF; // extracted lower 24 bits
    }
}

bool isHit(MCache *cache, Addr addr, Flag is_write, Flag yacc_mode)
{
    bool isHit=false;
    Addr tag = addr; 
    

    
    if(yacc_mode)
        isHit=mcache_access_yacc(cache,tag,is_write); 
    else
        isHit=mcache_access(cache,tag,is_write); 

    if(is_write)
        cache->s_write++;
    else
        cache->s_read++;


    return isHit;
}

MCache_Entry install(MCache *cache, Addr addr, Addr pc, Flag is_write, Flag yacc_mode, uns comp_size)
{
    Addr tag = addr;
    MCache_Entry victim;

    if(yacc_mode)
    {
        if(comp_size<=16)
            comp_size=16;
        else if(comp_size<=32)
            comp_size=32;
        else
            comp_size=64;

        victim = mcache_install_yacc(cache,tag,pc,is_write,comp_size);
    }
    else
        victim = mcache_install(cache,tag,pc,is_write);
    return victim;
}
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

void mcache_select_leader_sets(MCache *c, uns sets){
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

    uint32_t left_addr;
    uint32_t right_addr;

    left_addr = (uint32_t)((tag & 0xFFFFFF000000) >> 24);
    right_addr = (uint32_t)(tag & 0x000000FFFFFF);
    tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
    left_addr = (uint32_t)((tag & 0xFFFFFF000000) >> 24);
    right_addr = (uint32_t)(tag & 0x000000FFFFFF);
    if(addr != decrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys)){
        printf("Turns out Feistel isn't invertible!\n");
        exit(-1);
    }

    // If using CEASER
    if(c->APLR){
        // If we reached APLR accesses, we remap a set
        if(++c->ACtr >= c->APLR){
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
            if(++c->SPtr == c->sets){
                c->SPtr = 0;
                c->EpochID++;
                // Swap pointers and recreate new keys
                uint32_t *tmp = c->curr_keys;
                c->curr_keys = c->next_keys;
                c->next_keys = tmp;
                seedMT(c->EpochID+1);
                for(int round = 0; round < FEISTEL_ROUNDS; round++){
                    /* As randMT can only provide a 32 bit random number, we iterate on this 2 times per key */
                    c->next_keys[round] = randomMT();
                    /* As addresses are PHYSICAL_ADDR long, we need a key PHYSICAL_ADDR/2 in size */
                    c->next_keys[round] &= 0xFFFFFF; // extracted lower 24 bits
                }
            }
        }
    }


    // Split address into two 24 bits for encryption
    left_addr = (uint32_t)((addr & 0xFFFFFF000000) >> 24);
    right_addr = (uint32_t)(addr & 0x000000FFFFFF);
    tag = encrypt(left_addr, right_addr, FEISTEL_ROUNDS, c->curr_keys);
    set  = mcache_get_index(c,tag);
    Flag NextKey = 0;

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

bool mcache_access_yacc(MCache *c, Addr addr, Flag dirty)
{
    uns64 offset = c->lineoffset;
    Addr  sb_tag  = addr >> (offset+2); // full tags, offset for super block tag:(offset+2)
    uns   set  = mcache_get_index(c,sb_tag);
    uns   block_id = (addr >>(offset) & 0x3); //block id
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;
    c->s_count++;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == sb_tag) 
                && (entry->block_valid[block_id]==1))  //check block valid bit
        {
            entry->last_access  = c->s_count;
            entry->ripctr       = MCACHE_SRRIP_MAX;
            c->touched_wayid = (ii-start);
            c->touched_setid = set;
            c->touched_lineid = ii;
            if(dirty==TRUE) //If the operation is a WB then mark it as dirty
            {
                mcache_mark_dirty_yacc(c,sb_tag,set,block_id);
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


Flag mcache_probe_yacc    (MCache *c, Addr addr)
{
    uns64 offset = c->lineoffset;
    Addr  sb_tag  = addr>>(offset+2); // super block tag 
    uns   set  = mcache_get_index(c,sb_tag);
    Addr  block_id = (addr>>offset)&0x3;
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == sb_tag)
                &&(entry->block_valid[block_id]==1)) //check block valid bit
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

Flag mcache_mark_dirty_yacc (MCache *c, Addr tag, Addr set, uns block_id)
{
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii;

    for (ii=start; ii<end; ii++){
        MCache_Entry *entry = &c->entries[ii];
        if(entry->valid && (entry->tag == tag) && entry->block_valid[block_id])
        {
            entry->block_dirty[block_id] = TRUE;
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

    // If we are using CEASER
    if(c->APLR && set < c->SPtr || (dirty & NEXTKEY_MASK)){
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



    return evicted_entry;
}


MCache_Entry mcache_install_yacc(MCache *c, Addr addr, Addr pc, Flag dirty, uns comp_size)
{
    uns64 offset = c->lineoffset;
    Addr  sb_tag = addr>>(offset+2);  //calculate the super block tag
    Addr  block_id = (addr>>offset) &0x3;
    uns   set  = mcache_get_index(c,sb_tag); // use super block tag to get the set number
    uns   start = set * c->assocs;
    uns   end   = start + c->assocs;
    uns   ii, victim;

    Flag update_lrubits=TRUE;

    MCache_Entry *entry;
    MCache_Entry evicted_entry;

    for (ii=start; ii<end; ii++){
        entry = &c->entries[ii];
        if(entry->valid && (entry->tag == sb_tag))
        {
            if((entry->block_valid[block_id]==1)){ //YACC need to check the block valid bit
                fprintf(stderr,"YACC Installed entry already with addr:%llx present in set:%u tag:%llx block_id:%u\n", addr, set, sb_tag, block_id);
                exit(-1);
            }

            //A super block associated to new cache line is already in the cache, so check whether there is a room in this super block for the cache line
            bool has_room=false;
            if(comp_size==entry->comp_size) //the compressed cache size should be the same in a data block
            {
                if(comp_size<=16 && entry->block_cnt<=3)
                    has_room=true;
                else if(comp_size<=32 && entry->block_cnt==2)
                    has_room=true;
                else if (comp_size<=64)
                    has_room=false;
                else
                {
                    fprintf(stderr,"unsupported comp size: %d!\n",comp_size);
                    exit(-1);
                }
             }

            if(has_room==true)
            {
                if(comp_size<=16)
                    entry->block_cnt++;
                else if(comp_size<=32)
                    entry->block_cnt+=2;
                else if(comp_size<=64)
                {
                    fprintf(stderr,"there should not be any room!\n");
                    exit(-1);
                }
                entry->block_valid[block_id]=1;

                //set the dirty bit if needed
                if(dirty)
                    entry->block_dirty[block_id]=1;

                //printf("new compressed cache line is installed, addr:%llx tag:%llx set:%d block_id:%d comp_size:%d\n",addr,sb_tag,set, block_id, comp_size);
                return evicted_entry; //we install the compressed cache line in a data block. so just return empty entry (valid bit should be 0)
            }
         }
    }

    // find victim and install entry
    victim = mcache_find_victim(c, set);
    entry = &c->entries[victim];
    evicted_entry =c->entries[victim];


    //printf("victim cache line, tag:%llx set:%d\n",entry->tag,set);
    if(entry->valid){
        c->s_evict++;

        if(entry->dirty)
            c->s_writeback++;
    }
    

    uns ripctr_val=MCACHE_SRRIP_INIT;

    if(c->repl_policy==REPL_DRRIP){
        ripctr_val=mcache_drrip_get_ripctrval(c,set);
    }

    if(c->repl_policy==REPL_DIP){
        update_lrubits=mcache_dip_check_lru_update(c,set);
    }


    //put new information in
    entry->tag   = sb_tag;
    entry->valid = TRUE;
    entry->block_valid[block_id]=TRUE;
    entry->pc    = pc;

    entry->comp_size=comp_size;
    //printf("new cache line is installed, addr:%llx tag:%llx set:%d block_id:%d\n",addr,sb_tag,set, block_id);
    
    if(comp_size<=16)
        entry->block_cnt++;
    else if(comp_size<=32)
        entry->block_cnt+=2;
    else if(comp_size<=64)
        entry->block_cnt+=4;

    
    if(dirty==TRUE)
        entry->block_dirty[block_id]=TRUE;
    else
        entry->block_dirty[block_id] = FALSE;

    entry->ripctr  = ripctr_val;

    if(update_lrubits){
        entry->last_access  = c->s_count;
    }


    c->fifo_ptr[set] = (c->fifo_ptr[set]+1)%c->assocs; // fifo update

    c->touched_lineid=victim;
    c->touched_setid=set;
    c->touched_wayid=victim-(set*c->assocs);

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
