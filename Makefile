CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic
LDFLAGS=-lssl -lcrypto -luuid

BIN=tls_forward
SRC=src/tls_forward.c src/cache_lru.c src/filter.c src/logger.c

all: $(BIN)
$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)

# ---- Docker targets ----
docker-build:
	docker build -t reverse-proxy-secure .

docker-run:
	docker run --rm -p 4433:4433 reverse-proxy-secure

compose-up:
	docker compose up --build

compose-down:
	docker compose down
