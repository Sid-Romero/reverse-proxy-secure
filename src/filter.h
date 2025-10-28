#ifndef FILTER_H
#define FILTER_H

#include <regex.h>
#include <stdbool.h>

typedef struct {
    const char* pattern;
    regex_t regex;
} FilterRule;

typedef struct {
    FilterRule* rules;
    size_t count;
} FilterList;

int filter_init(FilterList* flist, const char* patterns[], size_t n);
void filter_free(FilterList* flist);
bool filter_match(FilterList* flist, const char* text);

#endif
