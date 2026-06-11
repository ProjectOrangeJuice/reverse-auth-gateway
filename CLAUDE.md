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
- `COOKIE_DOMAIN` (optional): Domain attribute for the session cookie. **Set this to the parent domain (e.g. `harriso.co.uk`) for multi-subdomain deployments** so one unlock covers `bit.`/`home.`/`unlock.` and, crucially, survives client IP changes (mobile, VPN, iCloud Private Relay — which rotate the source IP per connection). Unset = a host-only cookie scoped to the unlock subdomain, which will NOT be sent to the protected services, leaving them dependent on the IP allowlist alone.
- `COOKIE_NAME` (optional): Session cookie name (default: "gateway_session")
- `CLIENT_IP_HEADER` (optional): Header the fronting proxy uses to pass the real client IP (default: "X-Gateway-Client-IP"). The gateway trusts this because it is only reachable from Caddy over the internal network, and Caddy overwrites it per request from Cloudflare's `CF-Connecting-IP`. Falls back to the connecting IP if unset/missing/malformed. This is what makes IP whitelisting key on the per-visitor IP rather than a shared Cloudflare PoP.
- `TRUSTED_PROXIES` (optional): Comma-separated list of trusted proxy IPs/CIDRs. Defaults to private ranges plus Tailscale CGNAT. Cloudflare ranges are intentionally excluded — the real client IP arrives via `CLIENT_IP_HEADER`, not by walking X-Forwarded-For across Cloudflare.
- `ALLOW_LOCAL_BYPASS` (optional): Set to "true" to allow local IPs (192.168.0-29.x) to bypass authentication
- `IP_EXPIRATION_DAYS` (optional): Number of days before an authorized IP expires (default: 30)
- `MAX_LOGIN_FAILURES` (optional): Failed unlock attempts from one IP before it is locked out (default: 5)
- `LOCKOUT_MINUTES` (optional): How long a locked-out IP stays locked, returning HTTP 429 (default: 15)
- `PERSIST_FILE` (optional): Path to file for persisting authorized IPs (default: "granted_ips.json")

## Architecture

### Main Entry Point
[gateway.go](gateway.go) - Sets up Gin router, configures rate limiting (5 req/sec with burst of 5), and defines routes:
- `POST /unlock` - Password authentication with rate limiting
- `GET /unlock` - Unlock page (no rate limit)
- `GET /access` - Authorization check endpoint (called by nginx auth_request)
- `/css/*` - Static CSS files

### Web Package Structure
All HTTP handlers and core logic are in the [web/](web/) package:

**[web/web.go](web/web.go)** - Core types and initialization:
- `Handlers` struct holds templates, password, authorized IPs (`granted` slice), and persistence config
- `authed` struct tracks the minimum auth state: IP, auth time, and session token
- Input validation functions check passwords for null bytes, valid UTF-8, and length limits
- `SetupHandlers()` loads HTML templates, restores persisted IPs, and starts expiration cleanup
- `loadGranted()` restores authorized IPs from JSON file on startup, skipping expired entries and deduping multiple records for the same IP
- `saveGranted()` persists current authorized IPs to JSON file (called after each new auth)
- `cleanupExpiredIPs()` background goroutine that removes expired IPs every hour
- `isExpired()` checks if an IP authorization has exceeded the expiration duration

**[web/unlock.go](web/unlock.go)** - Authentication flow:
- Validates password input against security criteria
- On correct password: adds or refreshes the IP in `granted`, reusing the existing session cookie for that IP, and persists to file
- On wrong password: logs the failed login IP without storing attempted passwords
- `addGranted()` stores `AuthedTime` as `time.Time` for expiration tracking and preserves one active session per IP

**[web/access.go](web/access.go)** - Authorization logic:
- Checks if client IP is in `granted` slice and verifies it hasn't expired
- Returns HTTP 401 if IP is found but has exceeded expiration duration
- Falls back to local IP bypass if `ALLOW_LOCAL_BYPASS=true` and IP matches 192.168.0-29.x

### Concurrency Patterns
- `grantedLock` (mutex) protects the `granted` slice
- Each `authed` record has `recordEditLock` (mutex) protecting its auth timestamp and session token

### Security Features
- Real client IP comes from `CLIENT_IP_HEADER` (Caddy → CF-Connecting-IP), so grants/checks key on the per-visitor IP, not a shared Cloudflare PoP (see `clientIP()` in [web/access.go](web/access.go))
- Per-IP lockout after `MAX_LOGIN_FAILURES` failed unlocks: returns HTTP 429 with `Retry-After` for `LOCKOUT_MINUTES` (see [web/lockout.go](web/lockout.go)). This is the primary brute-force defense on the cloud path, where fail2ban can't see the gateway logs.
- Failed unlock POSTs return HTTP 401 (distinguishable in access logs); the page still renders for the user
- Rate limiting on /unlock (2 req/sec, burst 5)
- Input validation for passwords (null bytes, UTF-8, length limits)
- Failed login attempts are logged without storing attempted password values
- Persist file is written atomically (temp file + rename, serialized behind `saveLock`) so a crash mid-write can't truncate it and drop every grant
- ReadHeaderTimeout of 3 seconds on HTTP server
- Local IP bypass requires explicit opt-in via environment variable

## Testing Strategy
Tests cover:
- Session-cookie setting and rejection behavior in [web/access_test.go](web/access_test.go)
- Reusing the same session for repeat grants from one IP
- Startup dedupe of persisted records for the same IP
- Redacting query strings from Gin access logs in [gateway_test.go](gateway_test.go)
- Accepting trusted proxy IP and CIDR values
- Rate limiting behavior tests

## Docker Deployment
The [Dockerfile](Dockerfile) uses a `FROM scratch` base image (minimal attack surface) and copies:
- Pre-built `gateway` binary
- `web/src/` directory (HTML templates and CSS)

Deploy the saved image with:
```bash
docker load < gatewayDocker
```
