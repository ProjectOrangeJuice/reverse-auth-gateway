
Security Audit — reverse-auth-gateway + railway-proxy
The architecture as I understand it
Client → Cloudflare → Railway edge → Caddy (railway-proxy) → forward_auth to gateway for an allow/deny, and in parallel reverse_proxy over the Tailscale SOCKS5 tunnel → on-prem tunnel-nginx → local-caddy → homelab services. Auth is purely client-IP based (plus a session cookie), unlocked once via a single shared password.

That IP-based core is where most of the risk concentrates.

Critical
1. IP-based auth behind a shared proxy = password-free access for strangers
The whole trust model is "if your client IP is on the granted list, you're in" (web/access.go:33-45). Behind Cloudflare, your visitors don't have unique IPs — everyone exiting a given Cloudflare PoP shares a handful of edge IPs. So:

User A (legitimately, with the password) unlocks → the gateway stores the Cloudflare PoP IP.
Attacker B, same region, never had the password, browses to home.harriso.co.uk through the same PoP → g.ClientIP() resolves to the same PoP IP → match → 200 OK, full access to every protected service for up to 30 days.
The per-browser session cookie doesn't save you here: the cookie is checked first, but when it's absent the code falls through to the IP check and grants access anyway (web/access.go:16-45). IP is simply not an authenticator behind a shared egress (Cloudflare, corporate NAT, CGNAT, mobile carriers).

Recommendation: treat the password+cookie as the real auth and demote IP to at most a soft signal — or, if you keep IP allow-listing, resolve the true client IP (see #2) and accept that NAT/VPN co-tenants will still share access. Honestly the cleanest fix is "valid session cookie required; IP is only used to scope who may set a cookie."

2. The two layers disagree on which proxies to trust → client IP is wrong
Gateway trusts private ranges + all Cloudflare ranges (gateway.go:19-52).
Cloud Caddy trusts private_ranges 100.64.0.0/10 and not Cloudflare (railway-proxy/Caddy/Caddyfile:5).
Because Caddy resolves client_ip before forward_auth and passes its own resolved value downstream, Caddy's choice wins. Not trusting Cloudflare means Caddy stops walking X-Forwarded-For at the first untrusted hop — the Cloudflare edge IP — so geoblocking and rate-limiting are evaluated on the Cloudflare PoP, not the visitor. Geoblock becomes effectively random/ineffective, and all users collapse into one rate-limit bucket. The Cloudflare ranges added to the gateway (commit cdaec2e) don't help, because Caddy already collapsed the chain.

Recommendation: make both layers trust exactly the fronting infra (Railway edge + Cloudflare) and nothing else, or prefer Cloudflare's CF-Connecting-IP. Don't blanket-trust private_ranges/10.0.0.0/8 — that's far broader than the one hop in front of you.

3. fail2ban bans shared Cloudflare IPs and bans on normal "not-yet-unlocked" traffic
The on-prem filter bans on status 401|418 (roles/fail2ban/templates/caddy-auth.conf.j2). But 418 is what the gateway returns for every unauthorized-but-legitimate visitor (the replace_status @unauth 418 rewrite). Combined with #1/#2, the banned remote_ip is a Cloudflare PoP. Net effect: one person poking the site pre-unlock can get an entire Cloudflare PoP banned, locking out many real users. Also note the cloud railway-proxy has no fail2ban at all (managed container, stdout logs), so brute-force defense there is only tollbooth.

Recommendation: ban only on /unlock POST failures, key on the true client IP, and never auto-ban shared-proxy IPs.

High
4. Compromise of the Railway container = pivot into the home network
The internet-facing Caddy container holds a live Tailscale node with ALL_PROXY=socks5://localhost:1055 (railway-proxy/Caddy/start.sh:23) and proxies to the homelab with tls_insecure_skip_verify. Any RCE in Caddy or a third-party plugin (caddy-ratelimit, caddy-maxmind-geolocation) gives an attacker a tunnel into 192.168.x. Userspace networking limits it somewhat, but ALL_PROXY will route arbitrary egress through the tailnet.

Recommendation: lock this down at the tailnet level — ACL-tag the railway-proxy node so it can reach only tunnel-nginx:80/443 and nothing else on the tailnet. Ephemeral key + state=mem: is good; ACLs are the missing piece. This is your blast-radius control and right now I don't see it enforced.

5. Single shared password, weak brute-force ceiling on the cloud path
One GATEWAY_PASSWORD for everyone, constant-time compared (good — web/unlock.go:23), but the only throttle on the cloud is tollbooth at 5 req/s/IP (gateway.go:75-76) — ~432k guesses/day per IP, and an attacker spreading across source IPs parallelizes it. No lockout, no backoff, no CAPTCHA. Security rests entirely on the password's entropy.

Recommendation: ensure the password is long/random, lower the unlock rate limit hard, and consider an exponential backoff or a short hard lock after N failures.

6. Persist-file write is racy and non-atomic → can lose all grants
Every grant fires go h.saveGranted() (web/unlock.go:49,63), and saveGranted does a plain os.WriteFile (web/web.go:261). Concurrent goroutines can interleave writes, and a crash/OOM mid-write (you run with GOMEMLIMIT=64MiB/128M caps) leaves a truncated file. On restart json.Unmarshal fails and every authorized IP is dropped (web/web.go:166-168) — an availability hit forcing everyone to re-auth.

Recommendation: serialize saves behind a dedicated mutex and write-temp-then-os.Rename for atomicity.

Medium
7. DoS surface on the streaming route + single-threaded Caddy
The home route uses flush_interval -1 with zero read/write timeouts (railway-proxy/Caddy/Caddyfile:130-137), and the cloud Caddy runs GOMAXPROCS=1 with tight memory limits. A handful of slowloris / long-lived connections can starve the worker, and any flood of authorized traffic saturates the userspace Tailscale tunnel straight through to the homelab. The gateway itself has sane server timeouts (gateway.go:93-96); Caddy on this route does not.

Recommendation: add a per-route concurrency/in-flight cap and non-zero header/read timeouts even on streaming routes; rely on Cloudflare for volumetric absorption (which again requires #2 so CF actually sees real IPs for its own rules).

8. 30-day IP grants + IP churn hand access to the next holder
Grants live 30 days (web/web.go:71) keyed on IP. CGNAT/mobile/DHCP reassign public IPs among unrelated users constantly. Whoever inherits a previously-authorized IP within the window gets in with no password.

Recommendation: shorten the IP TTL substantially, or (better) stop granting on IP and grant on the cookie.

9. Sessions can't be revoked, cookie not bound to IP, 30-day lifetime
A leaked gateway_session cookie grants access from anywhere for 30 days (web/access.go:91-94). There's no logout/revoke endpoint and the session isn't tied to the IP that created it. Cookie flags themselves are good (Secure, HttpOnly, SameSite=Lax).

Recommendation: add a revoke path and consider binding/rotating sessions; shorten lifetime.

10. Overly broad trusted-proxy lists
Both layers trust all RFC1918 + CGNAT + (gateway) every Cloudflare range (gateway.go:19-52). Even though the gateway isn't internet-exposed (127.0.0.1:9090 on-prem, *.railway.internal on cloud — good), blanket-trusting 10.0.0.0/8 etc. is more spoofing surface than necessary for a single known front hop. See #2 — narrow it.

11. ALLOW_LOCAL_BYPASS is fragile (correctly off in prod)
checkLocalIP only validates the third octet and trusts 192.168.0-29.x derived from g.ClientIP() (web/access.go:58-84). If ever enabled where XFF can carry a private IP that a trusted hop forwards, it's an auth bypass — and each bypass also triggers a new grant + email + file write. It's not set in the cloud compose (good).

Recommendation: keep it disabled in any internet-facing deployment; document that explicitly; tighten the IP parsing if kept.

Low / hardening
Email header injection (low): ip is interpolated into the SMTP Subject/From/To block (web/email.go:18-23). Gin's ClientIP() returns a validated IP so this is currently safe, but sanitize/net.ParseIP-guard before composing headers as defense-in-depth. Also net/smtp.PlainAuth correctly refuses to auth without STARTTLS — fine.
Unbounded goroutines: every new grant spawns go saveGranted + go sendUnlockNotification (web/unlock.go:63-64); a churn of distinct authorized IPs could pile these up. Minor.
No per-service authorization: one unlock = access to all protected hosts (bit, home) for the full window. By design, but worth stating.
Stale committed GeoIP DB (GeoLite2-Country_20251003, dated Oct 2025, baked into the image) — geo decisions drift as IP allocations change; also a licensing consideration for committing the MaxMind DB to git.
Port inconsistency: railway-proxy Caddy talks to the gateway on :8080 (railway-proxy/Caddy/Caddyfile:59, :151) while the gateway defaults to 9090 and the IaC/.env.example say 9090. Not a vuln, but a config-drift footgun — confirm PORT=8080 is actually set on Railway or these routes 502.
tls_insecure_skip_verify to the tunnel is acceptable only because Tailscale (WireGuard) encrypts it; it does rely entirely on tailnet integrity — which loops back to the ACL recommendation in #4.
Good things worth keeping: constant-time password + session compares, crypto/rand 32-byte sessions, 0600 persist file, admin off, read_only + cap_drop: ALL + no-new-privileges containers, scratch/distroless gateway image, query-string redaction in logs, security headers, and failed logins logged without the attempted password.
Top 3 to fix first
Stop trusting IP as an authenticator behind Cloudflare (#1) — require the session cookie; this single change neutralizes the "stranger on the same PoP gets in" break.
Make trusted-proxy config consistent and narrow across both layers (#2) so geoblock/rate-limit/fail2ban operate on the real client IP — otherwise #3, #7, #8 all stay broken.
Lock down the tailnet ACLs for the Railway node (#4) to cap blast radius if the internet-facing container is ever popped.
Want me to turn any of these into actual code/config changes (e.g., the atomic-save fix in #6, cookie-required auth in #1, or aligned trusted_proxies)? I held off since you asked for an audit, not edits.