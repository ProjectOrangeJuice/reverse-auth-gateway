package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"
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

	local, record := h.checkLocalIP(connectorIP)
	if local {
		addAccess(record, g.Request.Host)
		g.Status(http.StatusOK)
		return
	}

	log.Printf("Rejecting access for %s (trying to access %s)", connectorIP, g.Request.Host)
	g.Status(http.StatusUnauthorized)
}

func (h *Handlers) checkLocalIP(ip string) (bool, *authed) {
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
		log.Printf("This is a local IP (%s), adding it to the allowed list", ip)
		return true, h.addGranted(ip)
	}
	return false, nil
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
