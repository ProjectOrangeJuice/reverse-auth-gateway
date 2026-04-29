package web

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AccessPage(g *gin.Context) {
	connectorIP := g.ClientIP()

	// Record access page visit metrics
	h.metrics.AccessPageVisits.Inc()
	h.recordAccessRequest(g)
	h.logAccessDebug(g, connectorIP)

	if session, err := g.Cookie(h.cookieName); err == nil {
		if authRecord := h.findGrantedBySession(session); authRecord != nil {
			if h.isExpired(authRecord) {
				log.Printf("Session for IP %s has expired (authed %v)", authRecord.IP, authRecord.AuthedTime)
				h.clearSessionCookie(g)
			} else {
				addAccess(authRecord, g.Request.Host)
				g.Status(http.StatusOK)
				return
			}
		}
	}

	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	for _, authRecord := range copiedGranted {
		if authRecord.IP == connectorIP {
			// Check if IP has expired
			if h.isExpired(authRecord) {
				log.Printf("IP %s has expired (authed %v)", connectorIP, authRecord.AuthedTime)
				g.Status(http.StatusUnauthorized)
				return
			}
			addAccess(authRecord, g.Request.Host)
			h.setSessionCookie(g, authRecord)
			g.Status(http.StatusOK)
			return
		}
	}

	local, record := h.checkLocalIP(connectorIP)
	if local {
		addAccess(record, g.Request.Host)
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

func (h *Handlers) recordAccessRequest(g *gin.Context) {
	host := g.Request.Host
	if len(host) > 253 {
		host = host[:253]
	}
	request := AccessRequest{
		IP:        g.ClientIP(),
		Timestamp: time.Now(),
		UserAgent: g.GetHeader("User-Agent"),
		Host:      sanitizeForLog(host),
		Method:    g.Request.Method,
	}

	h.metrics.AccessRequests.Inc()

	h.metrics.lock.Lock()
	h.metrics.AccessDetails = append(h.metrics.AccessDetails, request)
	// Keep only last 1000 requests to prevent memory issues
	if len(h.metrics.AccessDetails) > 1000 {
		h.metrics.AccessDetails = h.metrics.AccessDetails[len(h.metrics.AccessDetails)-1000:]
	}
	h.metrics.lock.Unlock()
}

func (h *Handlers) clearSessionCookie(g *gin.Context) {
	g.SetSameSite(http.SameSiteLaxMode)
	g.SetCookie(h.cookieName, "", -1, "/", h.cookieDomain, true, true)
}

func (h *Handlers) setSessionCookie(g *gin.Context, authRecord *authed) {
	g.SetSameSite(http.SameSiteLaxMode)
	g.SetCookie(h.cookieName, authRecord.Session, h.cookieMaxAgeSeconds(), "/", h.cookieDomain, true, true)
}

func (h *Handlers) logAccessDebug(g *gin.Context, clientIP string) {
	if os.Getenv("ACCESS_DEBUG") != "true" {
		return
	}

	upgrade := g.GetHeader("Upgrade")
	cookieDebug := h.accessCookieDebug(g.Request)
	log.Printf(
		"ACCESS_DEBUG client_ip=%q remote_addr=%q host=%q method=%q request_uri=%q user_agent=%q x_forwarded_for=%q x_real_ip=%q forwarded=%q x_forwarded_host=%q x_forwarded_proto=%q x_forwarded_method=%q x_forwarded_uri=%q upgrade=%q connection=%q is_websocket=%t cookie_count=%d cookie_names=%q gateway_cookie_present=%t gateway_cookie_count=%d gateway_cookie_valid=%t gateway_cookie_expired=%t gateway_cookie_record_ip=%q",
		sanitizeForLog(clientIP),
		sanitizeForLog(g.Request.RemoteAddr),
		sanitizeForLog(g.Request.Host),
		sanitizeForLog(g.Request.Method),
		safeAccessDebugURI(g),
		sanitizeForLog(g.GetHeader("User-Agent")),
		sanitizeForLog(g.GetHeader("X-Forwarded-For")),
		sanitizeForLog(g.GetHeader("X-Real-IP")),
		sanitizeForLog(g.GetHeader("Forwarded")),
		sanitizeForLog(g.GetHeader("X-Forwarded-Host")),
		sanitizeForLog(g.GetHeader("X-Forwarded-Proto")),
		sanitizeForLog(g.GetHeader("X-Forwarded-Method")),
		sanitizeForLog(g.GetHeader("X-Forwarded-Uri")),
		sanitizeForLog(upgrade),
		sanitizeForLog(g.GetHeader("Connection")),
		strings.EqualFold(upgrade, "websocket"),
		cookieDebug.Count,
		cookieDebug.Names,
		cookieDebug.GatewayPresent,
		cookieDebug.GatewayCount,
		cookieDebug.GatewayValid,
		cookieDebug.GatewayExpired,
		sanitizeForLog(cookieDebug.GatewayRecordIP),
	)
}

type accessCookieDebug struct {
	Count           int
	Names           string
	GatewayPresent  bool
	GatewayCount    int
	GatewayValid    bool
	GatewayExpired  bool
	GatewayRecordIP string
}

func (h *Handlers) accessCookieDebug(request *http.Request) accessCookieDebug {
	cookies := request.Cookies()
	debug := accessCookieDebug{
		Count: len(cookies),
		Names: summarizeCookieNames(cookies),
	}

	for _, cookie := range cookies {
		if cookie.Name != h.cookieName {
			continue
		}

		debug.GatewayPresent = true
		debug.GatewayCount++
		if authRecord := h.findGrantedBySession(cookie.Value); authRecord != nil {
			debug.GatewayValid = true
			debug.GatewayExpired = h.isExpired(authRecord)
			debug.GatewayRecordIP = authRecord.IP
		}
	}

	return debug
}

func summarizeCookieNames(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}

	counts := make(map[string]int, len(cookies))
	orderedNames := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if _, ok := counts[cookie.Name]; !ok {
			orderedNames = append(orderedNames, cookie.Name)
		}
		counts[cookie.Name]++
	}

	parts := make([]string, 0, len(orderedNames))
	for _, name := range orderedNames {
		part := sanitizeForLog(name)
		if counts[name] > 1 {
			part += "*" + strconv.Itoa(counts[name])
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, ",")
}

func safeAccessDebugURI(g *gin.Context) string {
	if g.Request.URL == nil {
		return ""
	}

	requestURI := g.Request.URL.EscapedPath()
	if requestURI == "" {
		requestURI = "/"
	}
	if g.Request.URL.RawQuery != "" {
		requestURI += "?<redacted>"
	}

	return sanitizeForLog(requestURI)
}
