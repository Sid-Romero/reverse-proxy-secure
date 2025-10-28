#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// OpenSSL headers - needs OpenSSL dev packets (libssl-dev)
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LISTEN_PORT 4433
#define BACKLOG 128
#define RECV_BUF 8192

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static int make_listen_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        perror("setsockopt"); close(fd); exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
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

    // Optionnel mais recommandé: n’autoriser que TLS 1.2+ (idéalement 1.3)
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

    // Bonnes pratiques de base (OpenSSL ≥1.1.1): préférences serveur
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    return ctx;
}

int main(void) {
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    int lfd = make_listen_socket();
    SSL_CTX *ctx = make_server_ctx("certs/server.crt", "certs/server.key");

    fprintf(stderr, "[*] TLS terminator listening on 0.0.0.0:%d\n", LISTEN_PORT);
    fprintf(stderr, "[*] Ctrl+C to stop\n");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: 27\r\n"
        "Connection: close\r\n"
        "\r\n"
        "Hello from TLS terminator\n";

    while (!g_stop) {
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli);
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

        // Lecture non bloquante du début de la requête HTTP (optionnel à ce stade)
        char buf[RECV_BUF];
        int n = SSL_read(ssl, buf, sizeof(buf));
        (void)n; // ignoré en Phase 1

        // Réponse fixe
        if (SSL_write(ssl, resp, (int)strlen(resp)) <= 0) {
            ERR_print_errors_fp(stderr);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }

    SSL_CTX_free(ctx);
    close(lfd);
    EVP_cleanup();
    return 0;
}
