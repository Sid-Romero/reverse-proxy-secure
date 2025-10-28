#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>

// Log an event in JSON format
// action: "FORWARD", "CACHE_HIT", "CACHE_STORE", "FILTER_BLOCKED", "ERROR"
// status: HTTP status code
void log_json(const char* client_ip, int client_port,
              const char* method, const char* url,
              const char* action, int status, size_t length);

#endif
