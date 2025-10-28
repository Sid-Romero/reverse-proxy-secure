CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic
LDFLAGS=-lssl -lcrypto

BIN=tls_hello

all: $(BIN)

$(BIN): src/tls_hello.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)
