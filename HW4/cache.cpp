#include "cache.h"

u64 CLOCK;

u64 Replace_LRU( Cache* cache, u64 new_addr ) {

    u32 set = new_addr & (cache->set_count - 1);
    u64 min_time = UINT64_MAX;
    int ind = -1;

    for( int assoc = 0; assoc < cache->associativity; assoc++ ) {
        if ( cache->_Cache[set][assoc].ref_time < min_time ) {
            ind = assoc;
            min_time = cache->_Cache[set][assoc].ref_time;
        }
    }
    u64 ret_addr = cache->_Cache[set][ind].tag << (BITLEN(cache->set_count)+cache->block_bits);
    cache->_fillBlock(new_addr, set, ind);
    return ret_addr;
}


u64 Replace_SRRIP( Cache* cache, u64 new_addr ) {

    u32 set = new_addr & (cache->set_count - 1);
    int ind = -1;

    while ( 1 ) {

        for( int assoc = 0; assoc < cache->associativity; assoc++ ) {
            if ( cache->_Cache[set][assoc].age >= 3 ) {
                ind = assoc;
                break;
            }
        }
        if ( ind != -1 ) break;

        for( int assoc = 0; assoc < cache->associativity; assoc++ ) {
            cache->_Cache[set][assoc].age++;
        }
    }
    u64 ret_addr = cache->_Cache[set][ind].tag << (BITLEN(cache->set_count)+cache->block_bits);
    cache->_fillBlock(new_addr, set, ind);
    return ret_addr;

}

u64 Replace_NRU( Cache* cache, u64 new_addr ) {

    u32 set = new_addr & (cache->set_count - 1);
    int ind = -1;

    for( int assoc = 0; assoc < cache->associativity; assoc++ ) {
        if ( cache->_Cache[set][assoc].ref_bit == 0 ) {
            ind = assoc;
            break;
        }
    }
    u64 ret_addr = cache->_Cache[set][ind].tag << (BITLEN(cache->set_count)+cache->block_bits);
    cache->_fillBlock(new_addr, set, ind);
    return ret_addr;

}

Cache::Cache( int assoc, int blk_size, int size, u64 (*func_ptr)(Cache*, u64)) {
    associativity = assoc;
    block_bits = BITLEN(blk_size);
    cache_size = size;
    set_count = (size * 1024) / (assoc * blk_size);
    _replace = func_ptr;
    _Cache = (CacheBlock**) malloc(sizeof(CacheBlock*) * set_count);
    for ( int i = 0; i < set_count; i++ ) {
        _Cache[i] = (CacheBlock*) malloc(sizeof(CacheBlock) * assoc);
    }
}

void Cache::_updateHitCount( u32 set, u32 way ) {
    if ( !_Cache[set][way].is_valid ) return;
    int hit_cnt = _Cache[set][way].hits;
    if ( hit_cnt == 0 ) dead_on_fill++;
    else {
        one_hits++;
        if ( hit_cnt >= 2 ) two_hits++;
    }
}

void Cache::_updateRefBits( u32 set, u32 way ) {
    if ( !_Cache[set][way].is_valid ) return;

    int ind = -1;
    for( int assoc = 0; assoc < associativity; assoc++ ) {
        if ( _Cache[set][assoc].ref_bit == 0 ) {
            ind = assoc;
            break;
        }
    }
    if ( ind == -1 ) {
        for( int assoc = 0; assoc < associativity; assoc++ ) {
            _Cache[set][assoc].ref_bit = 0;
        }
        _Cache[set][way].ref_bit = 1;
    }

}

int Cache::_find( u64 addr ) {
    access_count++;
    u32 set = addr & (set_count - 1);
    u64 tag = addr >> BITLEN(set_count);

    int ind = -1;
    CacheBlock* blk;
    for( int assoc = 0; assoc < associativity; assoc++ ) {
        blk = &_Cache[set][assoc];
        if ( blk->is_valid && blk->tag == tag ) {
            ind = assoc;
            break;
        }
    }

    if ( ind == -1 ) {
        miss_count++;
        return CACHE_MISS;
    }
    else {
        blk->hits++;
        blk->ref_time = CLOCK;
        blk->age = 0;
        blk->ref_bit = 1;
        _updateRefBits(set, ind);
        return CACHE_HIT;
    }
}

void Cache::_fillBlock( u64 addr, u32 set, u32 way ) {

    CacheBlock* blk = &_Cache[set][way];
    _updateHitCount(set, way);
    blk->is_valid = true;
    blk->ref_bit = 1;
    blk->tag = addr >> BITLEN(set_count);
    blk->hits = 0;
    blk->age = 2;
    blk->ref_time = CLOCK;
    blocks_filled++;
    _updateRefBits(set, way);

}

int Cache::_isSetFull( u64 addr ) {

    u32 set = addr & (set_count - 1);
    int ind = -1;

    for( int assoc = 0; assoc < associativity; assoc++ ) {
        if ( !_Cache[set][assoc].is_valid ) {
            ind = assoc;
            break;
        }
    }
    if ( ind == -1 ) return 1;
    else {
        _fillBlock(addr, set, ind);
        return 0;
    }
}

void Cache::_evict( u64 addr ) {
    u32 set = addr & (set_count - 1);
    u64 tag = addr >> BITLEN(set_count);

    int ind = -1;
    CacheBlock* blk;
    for( int assoc = 0; assoc < associativity; assoc++ ) {
        blk = &_Cache[set][assoc];
        if ( blk->is_valid && blk->tag == tag ) {
            ind = assoc;
            break;
        }
    }

    if ( ind != -1 ) {
        _updateHitCount(set, ind);
        blk->is_valid = 0;
    }
}

void Inclusion_Policy( Cache* L1, Cache* L2, u64 addr, int opsize, u64 clk ) {

    CLOCK = clk;
    u64 max_addr = (addr + opsize) >> L1->block_bits;
    u64 tmp_addr = addr >> L1->block_bits;

    //Going through different L1 cache blocks accesses needed for this address and operand size
    while ( tmp_addr <= max_addr ) {

        //In this implementation block offset is removed when accessing cache
        int res_L1 = L1->_find(tmp_addr);
        if ( res_L1 == CACHE_MISS ) {

            //If L1 miss then accessing L2 with relevent address (only TAG+SET)
            u64 L2_addr = (tmp_addr << L1->block_bits) >> L2->block_bits;
            int res_L2 = L2->_find(L2_addr);
            if ( res_L2 == CACHE_MISS ) {

                //In case of L2 miss, filling this new address in L2
                if ( L2->_isSetFull(L2_addr) ) {

                    //If the set is full in L2 then clearing a cache block in L2
                    //and making a evict request to L1 for this address range
                    u64 evict_addr = L2->_replace(L2, L2_addr) >> L1->block_bits;
                    int ctr = 1 << (L2->block_bits - L1->block_bits);

                    while ( ctr > 0 ) {
                        L1->_evict(evict_addr);
                        evict_addr++;
                        ctr--;
                    }
                }

            }
            //Fixing the L1 miss by allocating it a cache block
            if ( L1->_isSetFull(tmp_addr) ) {
                L1->_replace(L1, tmp_addr);
            }
            
        }
        tmp_addr++;
    }

}

void Print_Stats( Cache* cache ) {
    std::cout << "Total cache access = " << cache->access_count;
    std::cout << "\nTotal cache misses = " << cache->miss_count;
    std::cout << "\nTotal blocks filled = " << cache->blocks_filled;
    std::cout << "\nDead on fill blocks = " << cache->dead_on_fill;
    std::cout << "\nBlocks with atleast one hit = " << cache->one_hits;
    std::cout << "\nBlocks with atleast two hits = " << cache->two_hits << std::endl;
}