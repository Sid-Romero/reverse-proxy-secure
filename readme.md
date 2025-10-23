# Reverse Proxy Secure

## Overview
This project implements a secure HTTPS reverse proxy using C/Node.js with OpenSSL.  
It provides TLS termination, request caching, URL filtering, and structured logging for enterprise-grade use cases.

## Objectives
- Terminate TLS connections with OpenSSL
- Forward requests to backend HTTP servers
- Implement in-memory LRU cache for responses
- Filter requests using regex on URLs and headers
- Generate JSON logs for later indexing in Elasticsearch

## Architecture


## Tech Stack
- C (libevent) / Node.js
- OpenSSL
- Linux

## Tasks
1. Accept HTTPS connections and decrypt using OpenSSL
2. Re-route requests to backend servers
3. Add caching layer (LRU)
4. Apply request filtering rules
5. Generate structured logs

## Usage
Setup instructions and build/run commands will be provided as the project evolves.
