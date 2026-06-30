// xorfilter_wrap.c
// All xor8/xor16 functions are inline in the header.
// This wrapper compiles them into callable exported symbols.

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// This define makes the header include the implementation
#define XOR_BUFFERED_POPULATE
#include "xorfilter.h"

// ── XOR8 ─────────────────────────────────────────────────────

// Allocate and initialize filter for n elements
// Returns pointer to heap-allocated xor8_t, or NULL on failure
xor8_t* wrap_xor8_build(uint64_t *keys, size_t n) {
    xor8_t *f = (xor8_t*)malloc(sizeof(xor8_t));
    if (!f) return NULL;
    if (!xor8_allocate((uint32_t)n, f)) {
        free(f);
        return NULL;
    }
    if (!xor8_buffered_populate(keys, (uint32_t)n, f)) {
        xor8_free(f);
        free(f);
        return NULL;
    }
    return f;
}

int wrap_xor8_contain(xor8_t *f, uint64_t key) {
    return xor8_contain(key, f) ? 1 : 0;
}

size_t wrap_xor8_size_bytes(xor8_t *f) {
    return xor8_size_in_bytes(f);
}

void wrap_xor8_free(xor8_t *f) {
    if (f) {
        xor8_free(f);
        free(f);
    }
}

// ── XOR16 ────────────────────────────────────────────────────

xor16_t* wrap_xor16_build(uint64_t *keys, size_t n) {
    xor16_t *f = (xor16_t*)malloc(sizeof(xor16_t));
    if (!f) return NULL;
    if (!xor16_allocate((uint32_t)n, f)) {
        free(f);
        return NULL;
    }
    if (!xor16_buffered_populate(keys, (uint32_t)n, f)) {
        xor16_free(f);
        free(f);
        return NULL;
    }
    return f;
}

int wrap_xor16_contain(xor16_t *f, uint64_t key) {
    return xor16_contain(key, f) ? 1 : 0;
}

size_t wrap_xor16_size_bytes(xor16_t *f) {
    return xor16_size_in_bytes(f);
}

void wrap_xor16_free(xor16_t *f) {
    if (f) {
        xor16_free(f);
        free(f);
    }
}
