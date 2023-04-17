package web

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AccessPage(g *gin.Context) {
	connectorIP := g.ClientIP()

	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	for _, authRecord := range copiedGranted {
		if authRecord.IP == connectorIP {
			addAccess(authRecord, g.Request.Host)
			g.Status(http.StatusOK)
			return
		}
	}
	log.Printf("Rejecting access for %s (trying to access %s)", connectorIP, g.Request.Host)
	g.Status(http.StatusUnauthorized)
}

func addAccess(a *authed, domain string) {
	log.Printf("%s accessed %s", a.IP, domain)

	a.recordEditLock.Lock()
	defer a.recordEditLock.Unlock()

	a.LastAccess = time.Now().Format(time.UnixDate)

	newDomain := true
	for _, d := range a.DomainsAccessed {
		if d == domain {
			newDomain = false
			break
		}
	}
	if newDomain {
		a.DomainsAccessed = append(a.DomainsAccessed, domain)
	}

	now := time.Now().UTC().Truncate(time.Hour)
	a.Requests[now]++
}
