CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic
LDFLAGS=-lssl -lcrypto

BIN=tls_forward
SRC=src/tls_forward.c src/cache_lru.c src/filter.c src/logger.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)
