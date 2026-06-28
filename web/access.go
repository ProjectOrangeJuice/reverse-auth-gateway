package web

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
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

	ipSplit := strings.Split(ip, ".")
	if len(ipSplit) != 4 {
		return false, nil
	}
	localDigit, err := strconv.Atoi(ipSplit[2])
	if err != nil {
		log.Printf("could not read digit, %v", err)
		return false, nil
	}

	if ipSplit[0] == "192" && ipSplit[1] == "168" && localDigit < 30 {
		log.Printf("Local IP bypass enabled: adding %s to allowed list", ip)
		record, err := h.addGranted(ip)
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
	g.SetSameSite(http.SameSiteLaxMode)
	g.SetCookie(h.cookieName, authRecord.Session, h.cookieMaxAgeSeconds(), "/", h.cookieDomain, true, true)
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
