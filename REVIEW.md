# Reverse Auth Gateway + Railway Proxy Design & Security Review

**Date:** 2026-06-28  
**Scope:** `reverse-auth-gateway/` and `railway-proxy/` folders  
**Goal:** Review the design of the reverse proxy setup that provides controlled access to on-prem services via Tailscale. Ensure only legitimate traffic reaches the homelab.

---

## Executive Summary

This system uses two Railway-hosted services to safely expose selected on-prem services:

- `railway-proxy` (Caddy) acts as the public reverse proxy and enforces the first layers of defense.
- `reverse-auth-gateway` (Go/Gin) acts as the authentication decision point using a shared password + IP grants + session cookies.

Traffic must pass Cloudflare → origin lock → geoblock → rate limits → auth gateway check before the Caddy container will forward it over Tailscale to `tunnel-nginx` on the tailnet.

**Core risk area:** The protection ultimately rests on a single shared password, per-IP grants, and domain-scoped session cookies. The Railway proxy container itself has direct Tailscale reach into the on-prem network.

A prior `security-review.md` (in `reverse-auth-gateway/`) already identified many issues. This document consolidates the full code + design review and produces a concrete, prioritized plan of recommended changes.

---

## Architecture Overview

### Data Flow

```
Client (browser)
  → Cloudflare (CF-Connecting-Ip, X-Origin-Auth transform rule)
  → Railway edge
  → Caddy (railway-proxy container on Railway)
      ├── Origin secret check (X-Origin-Auth)
      ├── Geoblock (GB only via MaxMind)
      ├── Rate limiting
      ├── Security headers
      └── For protected hosts (bit., home.):
            1. reverse_proxy to gateway /access (passes X-Gateway-Client-IP = {client_ip})
            2. If 2xx from gateway → promote Set-Cookie if present
            3. reverse_proxy over Tailscale (`transport tailscale proxy`)
                 → tunnel-nginx.tailb4d50a.ts.net:80 (on-prem)
                     → local services
```

### Key Components

**railway-proxy (Caddy)**

- `Caddy/Caddyfile` — all routing, snippets for `geoblock`, `security_headers`, `gateway` (auth), `reverse_proxy_forward`, rate limits.
- Top-level `tailscale { auth_key ... }` + `transport tailscale proxy` (via caddy-tailscale plugin).
- Uses `client_ip_headers Cf-Connecting-Ip` + `trusted_proxies static 0.0.0.0/0`.
- Special streaming config only on `home.harriso.co.uk`.
- `unlock.*` directly proxies selected paths to the gateway.
- Origin lock lives here.

**reverse-auth-gateway (Go)**

- `gateway.go` — Gin server, rate limiting (tollbooth), trusted proxies, security headers.
- `web/web.go` — `Handlers`, `authed` struct, persistence (atomic write), expiration, session generation, cookie handling.
- `web/access.go` — `/access` logic (cookie first, then IP match, then local bypass).
- `web/unlock.go` — password validation + `addGranted`.
- `web/lockout.go` — per-IP failure counting + lockouts.
- `web/email.go` — optional unlock notifications.
- Persist file: `granted_ips.json` (one record per IP with `IP`, `AuthedTime`, `Session`).
- Client IP is taken exclusively from `X-Gateway-Client-IP` (or Gin fallback).

**Session / Grant model**

- On successful `/unlock`: create/refresh `authed` record for the real client IP + generate 32-byte random session token.
- `/access` succeeds if:
  1. Valid `gateway_session` cookie matches a non-expired record, **or**
  2. The current client IP matches a non-expired grant (then a cookie is set), **or**
  3. Local bypass (opt-in only).
- Cookie can use `COOKIE_DOMAIN` (parent domain) so one unlock works across `bit.`, `home.`, `unlock.` and survives some IP changes.
- Default lifetime: 30 days (`IP_EXPIRATION_DAYS`).

**Tailscale integration**

- The railway-proxy Caddy instance joins the tailnet as a node.
- All outbound traffic to the homelab uses the Tailscale transport.
- Ephemeral auth key (good — no long-lived state on Railway).

---

## Strengths

- Real client IPs are propagated (`Cf-Connecting-Ip` → `X-Gateway-Client-IP`) instead of collapsing to Cloudflare PoP IPs.
- Cookie + parent `COOKIE_DOMAIN` provides a practical workaround for mobile/VPN/IP-churn clients.
- Atomic, serialized persistence with deduplication and repair logic on load (well tested).
- Per-IP lockout after N failures (primary brute-force defense on the cloud path).
- Origin secret header (`X-Origin-Auth`) as a critical "Phase 0" control that makes the broad `trusted_proxies` acceptable.
- Minimal gateway container (`FROM scratch`).
- Constant-time password and session comparisons.
- Query string redaction in logs.
- Caddy config uses reusable snippets.
- Lockout + rate limiting combination.

---

## Issues and Risks

### Critical

1. **IP + shared password is the authenticator**  
   A grant is tied to an IP (or cookie). Anyone sharing the same public IP (home NAT, CGNAT, office) after an unlock gets access for the full window. Cookie theft or prediction also grants full access.

2. **High blast radius on compromise of the proxy**  
   The Railway Caddy container is a live Tailscale node that can reach the on-prem network. RCE in Caddy or any plugin (`caddy-ratelimit`, `caddy-maxmind-geolocation`, `caddy-tailscale`) gives an attacker a direct path into the homelab.

3. **No revocation / session management**  
   No logout, no way to invalidate a cookie or IP grant. Leaked cookie = access for up to 30 days from anywhere.

4. **Reliance on a single secret + origin lock**  
   The entire client IP resolution (and therefore grants, rate limits, and geoblocking) depends on Cloudflare's transform rule continuing to inject `X-Origin-Auth` and `Cf-Connecting-Ip`. If that breaks, spoofing becomes possible because of `trusted_proxies 0.0.0.0/0`.

### High

5. **Port inconsistency** (already noted in `security-review.md`)  
   Caddyfile hardcodes `reverse-auth-gateway.railway.internal:8080`.  
   Gateway defaults to 9090. `.env.example` says 9090. Easy source of 502s.

6. **Stale/outdated documentation**  
   `railway-proxy/CLAUDE.md` and `README.md` describe an older architecture (manual `tailscaled`, `ALL_PROXY`, `/etc/hosts` population via jq). The current implementation uses the Caddy Tailscale plugin directly and a 5-line `start.sh`.

7. **Cookie promotion asymmetry**  
   The `@home` route promotes `X-Reverse-Auth-Set-Cookie` → `Set-Cookie`. The `@bit` route does not. New IP-based grants reached via `bit.harriso.co.uk` may fail to deliver the session cookie to the client.

8. **Broad resource limits + streaming path**  
   `GOMEMLIMIT`, `GOMAXPROCS=1`, and zero timeouts on the `home.` route create DoS / starvation risk for the single Caddy worker.

9. **IP grants survive too long by default** (30 days) and are never explicitly revocable.

### Medium

10. **Baked-in GeoIP database** (old snapshot committed to git and image).
11. **Hardcoded tailnet target** (`tunnel-nginx.tailb4d50a.ts.net`).
12. **Naive local bypass IP check** (string split on dots, third octet test).
13. **No health checks** or readiness endpoints.
14. **Generous rate limits** and limited observability.
15. **Fire-and-forget goroutines** on every grant (save + optional email).

### Low / Hygiene

- Unlock form lacks CSRF token (low impact here).
- Email code does basic header construction.
- No admin tooling to list/revoke current grants.
- Caddyfile is large and monolithic.

---

## Recommended Plan of Changes

### Phase 0 – Immediate Fixes (Correctness & Drift)

1. **Standardize the gateway port**
   - Pick one port (recommend 9090 to match docs and `.env.example`).
   - Update:
     - `railway-proxy/Caddy/Caddyfile` (two `reverse_proxy` lines)
     - `railway-proxy/.env.example`
     - `railway-proxy/CLAUDE.md`
     - `reverse-auth-gateway/CLAUDE.md`
   - Add an explicit `PORT` default or `ENV` in the gateway Dockerfile for clarity.

2. **Fix cookie header promotion for `bit.` host**
   - In `railway-proxy/Caddy/Caddyfile`, the `@bit` `handle` block must also apply the `header @reverse_auth_cookie +Set-Cookie ...` logic (or factor it into a shared snippet) after calling the gateway.

3. **Update documentation**
   - Rewrite the "Architecture", "start.sh", and environment variable sections of `railway-proxy/CLAUDE.md`.
   - Add a clear diagram or flow description covering:
     - Origin lock
     - Client IP resolution path
     - Cookie hoisting hack
     - When the gateway is bypassed (`/unlock` paths, static routes)
   - Document the full set of required Railway environment variables in `.env.example` with comments.

4. **Add health endpoints**
   - Gateway: `GET /health` that returns 200 with no side effects (bypass auth logic).
   - Add Railway health check configuration once the endpoint exists.
   - Optionally expose a lightweight Caddy health route.

### Phase 1 – Reduce Blast Radius & Strengthen Trust Boundaries

5. **Tailscale ACLs (highest leverage security control)**
   - Tag the `railway-proxy` node (e.g. `tag:railway-proxy`).
   - Write tailnet ACLs that permit it to reach **only** the necessary on-prem ports/hosts (`tunnel-nginx:80/443`).
   - Document the tag + ACL expectation in the Caddyfile comments, CLAUDE.md, and README.
   - This is the primary mitigation if the Railway container is ever compromised.

6. **Make origin lock dependency more visible**
   - Add comments or a small `log` directive when the secret check passes.
   - Consider moving geoblock and rate limiting behind the origin check (they already are in practice).

7. **Tighten local IP bypass**
   - Rewrite `checkLocalIP` in `web/access.go` using proper `net/netip` or `net.ParseCIDR` + explicit, documented ranges.
   - Keep the feature explicitly opt-in.

### Phase 2 – Improve Authentication Model

8. **Clarify and potentially strengthen the auth decision**
   - Preferred direction: treat a valid session cookie as the primary authenticator. Use the IP grant primarily to *scope who is allowed to obtain a cookie* after a successful password unlock.
   - This reduces the power of a raw IP match.
   - Implement a basic revocation mechanism:
     - `POST /revoke` (or GET with the cookie) that removes the matching session (and optionally the whole IP record).

9. **Configurable lifetimes + better session hygiene**
   - Make cookie Max-Age / expiration controllable separately from `IP_EXPIRATION_DAYS` if desired.
   - On successful cookie-based `/access`, optionally rotate or refresh the session token (trade-off with mobile clients).
   - Shorten the default `IP_EXPIRATION_DAYS` (e.g. 7 or less) and document the implications.

10. **Stronger unlock credentials (defense in depth)**
    - Enforce a high-entropy `GATEWAY_PASSWORD`.
    - Add TOTP (or another second factor) to the unlock flow.
    - Or explore short-lived one-time tokens delivered via the existing email notification path.

11. **Per-grant visibility & management**
    - Add an optional admin/debug view (protected by `DEBUG_TOKEN` or another secret) that lists active grants (sanitized) and allows selective revocation.

### Phase 3 – Reliability, Observability & Hardening

12. **Caddy hardening**
    - Add reasonable `read_timeout`, `write_timeout`, `header_timeout` even on the streaming route.
    - Add `max_conns` / concurrency controls or `handle` limits on expensive paths.
    - Review and tighten rate limit numbers (`events` / `window`).
    - Move the MaxMind DB download out of the committed tarball and into the Dockerfile build step.

13. **Observability improvements**
    - Consistent structured logging for auth decisions, grants, lockouts, origin checks, and cookie vs IP path taken.
    - Consider adding basic metrics (active grants, recent failures) if Railway or an external collector is available.

14. **Gateway robustness**
    - Serialize or bound the background save + email goroutines.
    - Make SMTP sending optional and timeout-protected.
    - Add graceful handling if the persist directory is missing or unwritable.

15. **On-prem side considerations** (outside these folders but important)
    - Ensure fail2ban (or equivalent) on the homelab only acts on real failure signals and never blindly bans Cloudflare/Railway ranges.
    - The on-prem nginx/Caddy should treat traffic arriving from the railway-proxy Tailscale IP as "pre-authenticated" and not re-apply weak auth.

### Phase 4 – Longer-term / Strategic

- Evaluate whether the custom gateway should evolve into (or be replaced by) a more standard forward-auth solution if per-user accounts or better revocation become requirements.
- Extract Caddy configuration into multiple files as complexity grows.
- Add end-to-end tests that simulate the full Cloudflare → Caddy → gateway → Tailscale path (difficult without a staging environment).
- Consider moving geoblocking and some rate limiting into Cloudflare rules for earlier, cheaper enforcement.

---

## Files Referenced

This review is located in `reverse-auth-gateway/REVIEW.md` (sibling to `railway-proxy/`).

### railway-proxy (sibling)
- [../railway-proxy/Caddy/Caddyfile](../railway-proxy/Caddy/Caddyfile)
- [../railway-proxy/Caddy/Dockerfile](../railway-proxy/Caddy/Dockerfile)
- [../railway-proxy/Caddy/start.sh](../railway-proxy/Caddy/start.sh)
- [../railway-proxy/CLAUDE.md](../railway-proxy/CLAUDE.md)
- [../railway-proxy/.env.example](../railway-proxy/.env.example)

### reverse-auth-gateway (this directory)
- [gateway.go](gateway.go)
- [web/web.go](web/web.go), [web/access.go](web/access.go), [web/unlock.go](web/unlock.go), [web/lockout.go](web/lockout.go), [web/email.go](web/email.go)
- [web/access_test.go](web/access_test.go), [gateway_test.go](gateway_test.go)
- [Dockerfile](Dockerfile)
- [CLAUDE.md](CLAUDE.md)
- [security-review.md](security-review.md)

---

## Summary of Top Recommended Actions

| Priority | Action | Key Files | Impact |
|----------|--------|-----------|--------|
| P0 | Fix port numbers & cookie promotion for bit. | Caddyfile, env, docs | Prevents subtle bugs & 502s |
| P0 | Update stale CLAUDE.md / docs | railway-proxy/CLAUDE.md | Maintainability |
| P1 | Document + enforce Tailscale ACLs | Caddyfile comments, docs, tailnet policy | Blast radius reduction |
| P1 | Add /health endpoints | gateway.go + Caddyfile | Ops / Railway health checks |
| P2 | Strengthen auth (cookie primary, revocation) | web/access.go, web/unlock.go, Caddyfile | Core security model |
| P2 | Shorten default expiration + add admin revoke | web/* + optional admin path | Reduces exposure window |
| P3 | Harden Caddy timeouts/resources + externalize GeoIP | Caddyfile, Dockerfile | Resilience |

---

## Notes & Trade-offs

- The current design is a pragmatic solution for personal on-prem access. It deliberately trades some security for convenience (IP grants + long cookies + single password).
- Moving to a stricter "valid session cookie required" model (IP only for initial grant) would be a significant security improvement with acceptable usability cost once `COOKIE_DOMAIN` is set.
- True per-user identity, short-lived tokens, or device-bound credentials would require a larger architectural shift (SSO, magic links, passkeys, etc.).
- The origin lock + explicit header passing pattern is correct and should be preserved.

---

This report was produced after reading the source, configuration, tests, prior security review, and documentation in both folders.

Next step suggestions:
- Pick items from Phase 0 and implement them.
- Decide on the desired auth policy (cookie-primary vs current hybrid) before making larger changes to `web/access.go`.

If you would like the report expanded, split into separate files, or any of the recommendations turned into concrete diffs, let me know.