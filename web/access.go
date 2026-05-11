package web

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AccessPage(g *gin.Context) {
	connectorIP := g.ClientIP()

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
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.grantedLock.Unlock()

	for _, authRecord := range copiedGranted {
		if authRecord.IP == connectorIP {
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
