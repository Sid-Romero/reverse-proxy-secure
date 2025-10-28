#include "filter.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int filter_init(FilterList* flist, const char* patterns[], size_t n) {
    flist->rules = calloc(n, sizeof(FilterRule));
    if (!flist->rules) return -1;
    flist->count = n;
    for (size_t i = 0; i < n; i++) {
        flist->rules[i].pattern = patterns[i];
        if (regcomp(&flist->rules[i].regex, patterns[i], REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
            fprintf(stderr, "Failed to compile regex: %s\n", patterns[i]);
            return -1;
        }
    }
    return 0;
}

void filter_free(FilterList* flist) {
    for (size_t i = 0; i < flist->count; i++) {
        regfree(&flist->rules[i].regex);
    }
    free(flist->rules);
    flist->rules = NULL;
    flist->count = 0;
}

bool filter_match(FilterList* flist, const char* text) {
    for (size_t i = 0; i < flist->count; i++) {
        if (regexec(&flist->rules[i].regex, text, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}
