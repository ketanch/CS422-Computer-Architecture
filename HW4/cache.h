#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <string>
#include <iostream>

#define CACHE_HIT 1
#define CACHE_MISS 0
#define BITLEN(x) (int)floor(log2(x))

enum {
    LRU,
    SRRIP,
    NRU,
    MAX_POLICY
} policies;

static std::string policy_name[MAX_POLICY] = {
    "LRU",
    "SRRIP",
    "NRU"
};

typedef unsigned long long u64;
typedef unsigned int u32;

typedef struct {
    u64 tag;            //Tag to be compared
    u64 ref_time;       //Last reference time of the cache block(for LRU)
    bool is_valid;      //Is the entry valid or not
    int age;            //2-bit age for SRRIP
    int ref_bit;        //REF bit for NRU policy
    int hits;
} CacheBlock;

class Cache {

  public:

    int associativity;
    int block_bits;         //Bits to represent block offset
    int cache_size;         //Size of cache in KB
    int set_count;

    int access_count;       //Total accesses
    int miss_count;         //Total misses
    int dead_on_fill;       //Blocks which gets evicted before experiencing any hit
    int one_hits;           //Blocks which gets evicted and have atleast one hit
    int two_hits;           //Blocks which gets evicted and have atleast two hit
    int blocks_filled;      //Total blocks filled in cache

    CacheBlock** _Cache;
    u64 (*_replace)(Cache*, u64);

    Cache( int assoc, int blk_size, int size, u64 (*func_ptr)(Cache*, u64));
    void _updateHitCount( u32 set, u32 way );
    void _updateRefBits( u32 set, u32 way );
    int _find( u64 addr );
    void _fillBlock( u64 addr, u32 set, u32 way );
    int _isSetFull( u64 addr );
    void _evict( u64 addr );

};

extern u64 Replace_LRU( Cache* cache, u64 new_addr );
extern u64 Replace_SRRIP( Cache* cache, u64 new_addr );
extern u64 Replace_NRU( Cache* cache, u64 new_addr );
extern void Print_Stats( Cache* cache );
extern void Inclusion_Policy( Cache* L1, Cache* L2, u64 addr, int opsize, u64 clk );

static u64 (*Replace_Policy[MAX_POLICY])(Cache*, u64) = {
    Replace_LRU,
    Replace_SRRIP,
    Replace_NRU
};