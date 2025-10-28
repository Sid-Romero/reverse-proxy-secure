#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cache_lru.h"   // <-- LRU cache header

#define LISTEN_PORT 4433
#define BACKLOG 128
#define RECV_BUF 8192

#define BACKEND_HOST "127.0.0.1"
#define BACKEND_PORT 8080

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* -------------------- Networking helpers -------------------- */

static int connect_tcp(const char* host, int port) {
    int fd = -1;
    struct addrinfo hints, *res = NULL, *rp = NULL;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int make_listen_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        perror("setsockopt"); close(fd); exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); exit(EXIT_FAILURE);
    }
    if (listen(fd, BACKLOG) < 0) {
        perror("listen"); close(fd); exit(EXIT_FAILURE);
    }
    return fd;
}

static SSL_CTX* make_server_ctx(const char* cert_path, const char* key_path) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }

#if defined(TLS1_3_VERSION)
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
#endif

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    return ctx;
}

/* -------------------- HTTP request reader -------------------- */

static long parse_content_length(const char* headers, size_t len) {
    const char* p = headers;
    const char* end = headers + len;
    while (p < end) {
        const char* cl = strcasestr(p, "Content-Length:");
        if (!cl) return -1;
        cl += strlen("Content-Length:");
        while (cl < end && (*cl == ' ' || *cl == '\t')) cl++;
        char *e = NULL;
        long v = strtol(cl, &e, 10);
        if (e != cl && v >= 0) return v;
        p = cl + 1;
    }
    return -1;
}

static int read_full_http_request_from_client(SSL* ssl, unsigned char** out_buf, size_t* out_len) {
    size_t cap = 16 * 1024;
    size_t len = 0;
    unsigned char* buf = malloc(cap);
    if (!buf) return -1;

    ssize_t n;
    while (1) {
        if (len == cap) {
            cap *= 2;
            unsigned char* tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return -1; }
            buf = tmp;
        }
        n = SSL_read(ssl, buf + len, (int)(cap - len));
        if (n <= 0) { free(buf); return -1; }
        len += (size_t)n;

        if (len >= 4) {
            for (size_t i = 0; i + 3 < len; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    size_t headers_len = i + 4;
                    long cl = parse_content_length((const char*)buf, headers_len);
                    if (cl <= 0) {
                        *out_buf = buf; *out_len = len;
                        return 0;
                    }
                    size_t target = headers_len + (size_t)cl;
                    while (len < target) {
                        if (len == cap) {
                            cap *= 2;
                            unsigned char* tmp2 = realloc(buf, cap);
                            if (!tmp2) { free(buf); return -1; }
                            buf = tmp2;
                        }
                        n = SSL_read(ssl, buf + len, (int)(cap - len));
                        if (n <= 0) { free(buf); return -1; }
                        len += (size_t)n;
                    }
                    *out_buf = buf; *out_len = len;
                    return 0;
                }
            }
        }
    }
}

/* -------------------- Proxy core with caching -------------------- */

static int forward_request_with_cache(SSL* ssl_client, LRUCache* cache) {
    // Step 1: Read request from client
    unsigned char* req = NULL; size_t req_len = 0;
    if (read_full_http_request_from_client(ssl_client, &req, &req_len) != 0) {
        return -1;
    }

    // Step 2: Extract method and URL from request line
    char method[8], url[1024];
    if (sscanf((char*)req, "%7s %1023s", method, url) != 2) {
        free(req);
        return -1;
    }

    // Build cache key as "METHOD URL"
    char key[2048];
    snprintf(key, sizeof(key), "%s %s", method, url);
    fprintf(stderr, "[DEBUG] Key built = %s\n", key);

    // Only cache GET requests
    if (strcmp(method, "GET") == 0) {
        size_t cached_len = 0;
        unsigned char* cached_val = lru_get(cache, key, &cached_len);
        if (cached_val) {
            // Cache HIT
            fprintf(stderr, "[CACHE HIT] %s\n", key);
            fprintf(stderr, "[DEBUG] Cache hit length = %zu\n", cached_len);
            SSL_write(ssl_client, cached_val, (int)cached_len);
            free(req);
            return 0;
        }
    }

    // Step 3: Forward request to backend
    int bfd = connect_tcp(BACKEND_HOST, BACKEND_PORT);
    if (bfd < 0) {
        free(req);
        const char* resp =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 15\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Gateway.\n";
        SSL_write(ssl_client, resp, (int)strlen(resp));
        return -1;
    }

    size_t off = 0;
    while (off < req_len) {
        ssize_t wn = send(bfd, req + off, req_len - off, 0);
        if (wn < 0) { close(bfd); free(req); return -1; }
        off += (size_t)wn;
    }
    free(req);

    // Collect full response from backend
    unsigned char* resp_buf = NULL;
    size_t resp_cap = 16 * 1024, resp_len = 0;
    resp_buf = malloc(resp_cap);

    for (;;) {
        unsigned char tmp[RECV_BUF];
        ssize_t rn = recv(bfd, tmp, sizeof(tmp), 0);
        if (rn == 0) break;
        if (rn < 0) { free(resp_buf); close(bfd); return -1; }
        if (resp_len + rn > resp_cap) {
            resp_cap *= 2;
            unsigned char* tmp2 = realloc(resp_buf, resp_cap);
            if (!tmp2) { free(resp_buf); close(bfd); return -1; }
            resp_buf = tmp2;
        }
        memcpy(resp_buf + resp_len, tmp, rn);
        resp_len += rn;
    }
    close(bfd);

    // Step 4: Send response to client
    SSL_write(ssl_client, resp_buf, (int)resp_len);

    // Step 5: Store in cache if GET
    if (strcmp(method, "GET") == 0) {
        lru_put(cache, key, resp_buf, resp_len);
        fprintf(stderr, "[CACHE STORE] %s (len=%zu)\n", key, resp_len);
        fprintf(stderr, "[DEBUG] Stored response length = %zu\n", resp_len);
    }

    free(resp_buf);
    return 0;
}

/* -------------------- Main -------------------- */

int main(void) {
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    int lfd = make_listen_socket();
    SSL_CTX *ctx = make_server_ctx("certs/server.crt", "certs/server.key");

    // Initialize cache with capacity = 100 entries
    LRUCache* cache = lru_create(100);

    fprintf(stderr, "[*] TLS reverse proxy listening on 0.0.0.0:%d → %s:%d\n",
            LISTEN_PORT, BACKEND_HOST, BACKEND_PORT);
    fprintf(stderr, "[*] Ctrl+C to stop\n");

    while (!g_stop) {
        struct sockaddr_storage cli; socklen_t clilen = sizeof(cli);
        int cfd = accept(lfd, (struct sockaddr *)&cli, &clilen);
        if (cfd < 0) {
            if (errno == EINTR && g_stop) break;
            perror("accept"); continue;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) { ERR_print_errors_fp(stderr); close(cfd); continue; }
        SSL_set_fd(ssl, cfd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); close(cfd); continue;
        }

        (void)forward_request_with_cache(ssl, cache);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }

    lru_free(cache);
    SSL_CTX_free(ctx);
    close(lfd);
    EVP_cleanup();
    return 0;
}
