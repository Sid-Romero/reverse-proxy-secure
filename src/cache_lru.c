#include "cache_lru.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// Simple hash
static size_t hash_str(const char *s) {
    size_t h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}

LRUCache* lru_create(size_t capacity) {
    LRUCache *c = calloc(1, sizeof(LRUCache));
    c->capacity = capacity;
    c->table = calloc(capacity * 2, sizeof(CacheEntry*));
    return c;
}

void lru_free(LRUCache *c) {
    if (!c) return;
    CacheEntry *cur = c->head;
    while (cur) {
        CacheEntry *n = cur->next;
        free(cur->key);
        free(cur->value);
        free(cur);
        cur = n;
    }
    free(c->table);
    free(c);
}

// Move entry to head
static void move_to_head(LRUCache *c, CacheEntry *e) {
    if (c->head == e) return;
    if (e->prev) e->prev->next = e->next;
    if (e->next) e->next->prev = e->prev;
    if (c->tail == e) c->tail = e->prev;
    e->prev = NULL;
    e->next = c->head;
    if (c->head) c->head->prev = e;
    c->head = e;
    if (!c->tail) c->tail = e;
}

unsigned char* lru_get(LRUCache *c, const char *key, size_t *out_len) {
    size_t idx = hash_str(key) % (c->capacity * 2);
    CacheEntry *e = c->table[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            move_to_head(c, e);
            *out_len = e->value_len;
            return e->value;
        }
        e = e->next;
    }
    return NULL;
}

int lru_put(LRUCache *c, const char *key,
            const unsigned char *value, size_t value_len) {
    // simplified: no resizing, no collision handling
    size_t idx = hash_str(key) % (c->capacity * 2);

    CacheEntry *e = c->table[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            free(e->value);
            e->value = malloc(value_len);
            memcpy(e->value, value, value_len);
            e->value_len = value_len;
            move_to_head(c, e);
            return 0;
        }
        e = e->next;
    }

    // Create new entry
    e = calloc(1, sizeof(CacheEntry));
    e->key = strdup(key);
    e->value = malloc(value_len);
    memcpy(e->value, value, value_len);
    e->value_len = value_len;

    // Insert at table[idx]
    e->next = c->table[idx];
    c->table[idx] = e;

    // Insert at head LRU
    e->prev = NULL;
    e->next = c->head;
    if (c->head) c->head->prev = e;
    c->head = e;
    if (!c->tail) c->tail = e;

    c->size++;
    // Eviction if capacity exceeded
    if (c->size > c->capacity) {
        CacheEntry *old = c->tail;
        if (old->prev) old->prev->next = NULL;
        c->tail = old->prev;
        free(old->key);
        free(old->value);
        free(old);
        c->size--;
    }
    return 0;
}
