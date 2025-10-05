# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a reverse authentication gateway written in Go. It acts as an authentication proxy that sits in front of services (typically used with nginx `auth_request`). The gateway validates client IPs against an authorized list before allowing access to protected resources.

**Core concept**: Services make requests to the `/access` endpoint. The gateway responds with HTTP 200 (authorized) or HTTP 401 (unauthorized) based on whether the client IP is in the authorized list.

## Build and Run

**Build the binary**:
```bash
./build.sh
```
This compiles a static binary for Linux (CGO_ENABLED=0), builds a Docker image, and exports it to `gatewayDocker`.

**Build manually**:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gateway
```

**Run locally**:
```bash
GATEWAY_PASSWORD=your_password ./gateway
```

The server listens on port 9090.

## Environment Variables

- `GATEWAY_PASSWORD` (required): Password for the `/unlock` endpoint
- `TRUSTED_PROXIES` (optional): Comma-separated list of trusted proxy IPs (e.g., "10.0.0.1,10.0.0.2")
- `ALLOW_LOCAL_BYPASS` (optional): Set to "true" to allow local IPs (192.168.0-29.x) to bypass authentication
- `IP_EXPIRATION_DAYS` (optional): Number of days before an authorized IP expires (default: 30)
- `PERSIST_FILE` (optional): Path to file for persisting authorized IPs (default: "granted_ips.json")

## Architecture

### Main Entry Point
[gateway.go](gateway.go) - Sets up Gin router, configures rate limiting (5 req/sec with burst of 5), and defines routes:
- `POST /unlock` - Password authentication with rate limiting
- `GET /unlock` - Unlock page (no rate limit)
- `GET /access` - Authorization check endpoint (called by nginx auth_request)
- `GET /metrics` - Prometheus metrics endpoint
- `/css/*` - Static CSS files

### Web Package Structure
All HTTP handlers and core logic are in the [web/](web/) package:

**[web/web.go](web/web.go)** - Core types and initialization:
- `Handlers` struct holds templates, password, authorized IPs (`granted` slice), metrics, and persistence config
- `authed` struct tracks per-IP data: auth time, last access, domains accessed, and hourly request buckets
- Input validation functions (`validatePassword`, `validateQueryParam`, `sanitizeForLog`) that check for null bytes, control characters, valid UTF-8, and length limits
- `SetupHandlers()` loads HTML templates, initializes Prometheus metrics, restores persisted IPs, and starts expiration cleanup
- `loadGranted()` restores authorized IPs from JSON file on startup, skipping expired entries
- `saveGranted()` persists current authorized IPs to JSON file (called after each new auth)
- `cleanupExpiredIPs()` background goroutine that removes expired IPs every hour
- `isExpired()` checks if an IP authorization has exceeded the expiration duration

**[web/unlock.go](web/unlock.go)** - Authentication flow:
- Validates password input against security criteria
- On correct password: adds IP to `granted` slice, spawns hourly cleanup goroutine, and persists to file
- On wrong password: records sanitized attempt in `activity` sync.Map
- `handleBucket()` goroutine prunes request buckets older than 7 days every hour
- `addGranted()` now stores `AuthedTime` as `time.Time` for expiration tracking

**[web/access.go](web/access.go)** - Authorization logic:
- Checks if client IP is in `granted` slice and verifies it hasn't expired
- Returns HTTP 401 if IP is found but has exceeded expiration duration
- Falls back to local IP bypass if `ALLOW_LOCAL_BYPASS=true` and IP matches 192.168.0-29.x
- Records access metrics (IP, timestamp, user agent, host, method) up to 1000 most recent requests
- `addAccess()` updates last access time, domains list, and increments hourly request counter

**[web/metrics.go](web/metrics.go)** - Exposes Prometheus metrics handler

**[web/bucket.go](web/bucket.go)** - Displays per-IP request bucket data (validates IP query parameter)

### Metrics
Prometheus counters exposed at `/metrics`:
- `gateway_access_page_visits_total` - Total `/access` endpoint visits
- `gateway_wrong_password_attempts_total` - Failed auth attempts
- `gateway_correct_password_attempts_total` - Successful auth attempts
- `gateway_access_requests_total` - Total access requests with detailed tracking

### Concurrency Patterns
- `auditLock` (mutex) protects the `granted` slice
- `activity` (sync.Map) stores failed login attempts per IP
- Each `authed` record has `recordEditLock` (mutex) protecting its request bucket map
- Each authed IP gets its own cleanup goroutine that runs hourly to prune old data

### Security Features
- Rate limiting on POST /unlock (5 req/sec, burst 5)
- Input validation for passwords and query parameters (null bytes, control chars, UTF-8, length limits)
- Password sanitization before logging to prevent log injection
- Request history limited to 1000 entries to prevent memory exhaustion
- ReadHeaderTimeout of 3 seconds on HTTP server
- Local IP bypass requires explicit opt-in via environment variable

## Testing Strategy
No test files currently exist. When adding tests, consider:
- Unit tests for input validation functions in [web/web.go](web/web.go)
- Integration tests for the auth flow (unlock → access)
- Concurrent access tests for the `granted` slice and request bucket cleanup
- Rate limiting behavior tests

## Docker Deployment
The [Dockerfile](Dockerfile) uses a `FROM scratch` base image (minimal attack surface) and copies:
- Pre-built `gateway` binary
- `web/src/` directory (HTML templates and CSS)

Deploy the saved image with:
```bash
docker load < gatewayDocker
```
