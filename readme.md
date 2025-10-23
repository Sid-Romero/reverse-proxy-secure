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
