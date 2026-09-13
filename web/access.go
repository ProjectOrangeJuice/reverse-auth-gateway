package web

import (
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AccessPage(g *gin.Context) {
	connectorIP := h.clientIP(g)

	if session, err := g.Cookie(h.cookieName); err == nil {
		if authRecord := h.findGrantedBySession(session); authRecord != nil {
			if h.isExpired(authRecord) {
				log.Printf("Session for IP %s has expired (authed %v)", authRecord.IP, authRecord.AuthedTime)
				h.clearSessionCookie(g)
			} else {
				g.Status(http.StatusOK)
				return
			}
		}
	}

	h.grantedLock.Lock()
	authRecord := h.granted[connectorIP]
	h.grantedLock.Unlock()

	if authRecord != nil {
		// Check if IP has expired
		if h.isExpired(authRecord) {
			log.Printf("IP %s has expired (authed %v)", connectorIP, authRecord.AuthedTime)
			g.Status(http.StatusUnauthorized)
			return
		}
		h.setSessionCookie(g, authRecord)
		g.Status(http.StatusOK)
		return
	}

	local, record := h.checkLocalIP(connectorIP)
	if local {
		h.setSessionCookie(g, record)
		g.Status(http.StatusOK)
		return
	}

	log.Printf("Rejecting access for %s (trying to access %s)", connectorIP, g.Request.Host)
	g.Status(http.StatusUnauthorized)
}

func (h *Handlers) checkLocalIP(ip string) (bool, *authed) {
	// Only allow local IP bypass if explicitly enabled via environment variable
	if os.Getenv("ALLOW_LOCAL_BYPASS") != "true" {
		return false, nil
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.Is4() {
		return false, nil
	}

	octets := addr.As4()
	// 192.168.0.0–192.168.29.255 — the on-prem LAN ranges this homelab uses.
	if octets[0] == 192 && octets[1] == 168 && octets[2] < 30 {
		log.Printf("Local IP bypass enabled: adding %s to allowed list", ip)
		record, err := h.addGranted(addr.String())
		if err != nil {
			log.Printf("could not create local bypass auth for %s: %v", ip, err)
			return false, nil
		}
		return true, record
	}
	return false, nil
}

func (h *Handlers) clearSessionCookie(g *gin.Context) {
	g.SetSameSite(http.SameSiteLaxMode)
	g.SetCookie(h.cookieName, "", -1, "/", h.cookieDomain, true, true)
}

func (h *Handlers) setSessionCookie(g *gin.Context, authRecord *authed) {
	session := snapshotPersisted(authRecord).Session
	g.SetSameSite(http.SameSiteLaxMode)
	g.SetCookie(h.cookieName, session, h.cookieMaxAgeSeconds(), "/", h.cookieDomain, true, true)
}

// RealClientIP returns the per-visitor client IP from the given header name
// when the header is present and contains a syntactically valid IP address.
// Returns "" otherwise so the caller can fall back (e.g. to gin's ClientIP()).
// This is the shared implementation used both by auth logic and by the
// Gin access log formatter so that logs show the real IP (not a Railway edge).
func RealClientIP(r *http.Request, headerName string) string {
	if r == nil || headerName == "" {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get(headerName)); v != "" {
		if net.ParseIP(v) != nil {
			return v
		}
	}
	return ""
}

// clientIP returns the real per-visitor IP. Behind Cloudflare + Railway, gin's
// ClientIP() resolves to a shared Cloudflare PoP address or Railway edge IP, so
// the fronting Caddy injects the resolved client IP via clientIPHeader (default
// X-Gateway-Client-IP). We trust that header because the gateway is only
// reachable from Caddy over the internal network. Falls back to gin's ClientIP()
// for local/dev, or if the header is missing or malformed.
func (h *Handlers) clientIP(g *gin.Context) string {
	if ip := RealClientIP(g.Request, h.clientIPHeader); ip != "" {
		return ip
	}
	if h.clientIPHeader != "" {
		if v := strings.TrimSpace(g.GetHeader(h.clientIPHeader)); v != "" {
			log.Printf("Ignoring invalid %s header %q from %v", h.clientIPHeader, v, g.ClientIP())
		}
	}
	return g.ClientIP()
}
