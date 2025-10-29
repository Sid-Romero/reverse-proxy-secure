# ---- Build stage ----
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    uuid-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy sources
COPY . .

# Build proxy
RUN make clean && make

# ---- Final runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libuuid1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary + certs from builder
COPY --from=builder /app/tls_forward /app/tls_forward
COPY --from=builder /app/certs /app/certs

# Create non-root user
RUN useradd -m proxyuser
USER proxyuser

EXPOSE 4433

CMD ["./tls_forward"]
