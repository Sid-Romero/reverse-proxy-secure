#ifndef CACHE_LRU_H
#define CACHE_LRU_H

#include <stddef.h>

typedef struct CacheEntry {
    char *key;              // methopd + URL
    unsigned char *value;   // response
    size_t value_len;
    struct CacheEntry *prev;
    struct CacheEntry *next;
} CacheEntry;

typedef struct {
    CacheEntry **table;
    size_t capacity;
    size_t size;
    CacheEntry *head;
    CacheEntry *tail;
} LRUCache;

LRUCache* lru_create(size_t capacity);
void lru_free(LRUCache *cache);

int lru_put(LRUCache *cache, const char *key,
            const unsigned char *value, size_t value_len);

unsigned char* lru_get(LRUCache *cache, const char *key, size_t *out_len);

#endif
