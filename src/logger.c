#include "logger.h"
#include <stdio.h>
#include <time.h>

// Format current time as ISO8601 UTC
static void current_time_iso8601(char* buf, size_t buflen) {
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void log_json(const char* client_ip, int client_port,
              const char* method, const char* url,
              const char* action, int status, size_t length) {
    char tbuf[64];
    current_time_iso8601(tbuf, sizeof(tbuf));

    // Print JSON log to stdout
    printf("{\"time\":\"%s\",\"client\":\"%s:%d\","
           "\"method\":\"%s\",\"url\":\"%s\","
           "\"action\":\"%s\",\"status\":%d,\"length\":%zu}\n",
           tbuf, client_ip, client_port,
           method ? method : "-", url ? url : "-",
           action, status, length);
    fflush(stdout);
}
