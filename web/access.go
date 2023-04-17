package web

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AccessPage(g *gin.Context) {
	connectorIP := g.ClientIP()

	if strings.Contains(connectorIP, "192.168.2.") {
		log.Printf("Allowing %s as local to access %s", connectorIP, g.Request.Host)
		g.Status(http.StatusOK)
		return
	}

	for _, i := range allowed {
		if i.IP == connectorIP {
			i.LastAccess = time.Now().Format(time.UnixDate)
			addDomain(i, g.Request.Host)
			g.Status(http.StatusOK)
			return
		}
	}
	log.Printf("Rejecting access for %s (trying to access %s)", connectorIP, g.Request.Host)
	g.Status(http.StatusUnauthorized)
}

func addDomain(a *authed, domain string) {
	log.Printf("%s accessed %s", a.IP, domain)
	for _, d := range a.DomainsAccessed {
		if d == domain {
			return
		}
	}
	a.DomainsAccessed = append(a.DomainsAccessed, domain)
}
