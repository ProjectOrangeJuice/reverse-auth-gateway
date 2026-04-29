package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAccessPageSetsSessionCookieForAuthorizedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers()
	h.granted = append(h.granted, &authed{
		IP:         "203.0.113.10",
		AuthedTime: time.Now(),
		Session:    "session-token",
		Requests:   make(map[time.Time]int),
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/access", nil)
	c.Request.RemoteAddr = "203.0.113.10:12345"

	h.AccessPage(c)

	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, c.Writer.Status())
	}

	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "gateway_session=session-token") {
		t.Fatalf("expected gateway session cookie, got %q", setCookie)
	}
}

func TestAccessPageDoesNotSetSessionCookieForExistingValidSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers()
	h.granted = append(h.granted, &authed{
		IP:         "203.0.113.10",
		AuthedTime: time.Now(),
		Session:    "session-token",
		Requests:   make(map[time.Time]int),
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/access", nil)
	c.Request.RemoteAddr = "198.51.100.20:12345"
	c.Request.AddCookie(&http.Cookie{Name: "gateway_session", Value: "session-token"})

	h.AccessPage(c)

	if c.Writer.Status() != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, c.Writer.Status())
	}
	if setCookie := w.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("expected no refreshed cookie for existing session, got %q", setCookie)
	}
}

func TestAccessPageDoesNotSetSessionCookieForUnauthorizedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/access", nil)
	c.Request.RemoteAddr = "198.51.100.20:12345"

	h.AccessPage(c)

	if c.Writer.Status() != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, c.Writer.Status())
	}
	if setCookie := w.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("expected no cookie for unauthorized request, got %q", setCookie)
	}
}

func TestAccessCookieDebugSummarizesCookieShapeWithoutValues(t *testing.T) {
	h := newTestHandlers()
	h.granted = append(h.granted, &authed{
		IP:         "203.0.113.10",
		AuthedTime: time.Now(),
		Session:    "valid-session",
		Requests:   make(map[time.Time]int),
	})

	request := httptest.NewRequest(http.MethodGet, "/access", nil)
	request.AddCookie(&http.Cookie{Name: "gateway_session", Value: "invalid-session"})
	request.AddCookie(&http.Cookie{Name: "ha_session", Value: "do-not-log"})
	request.AddCookie(&http.Cookie{Name: "gateway_session", Value: "valid-session"})

	debug := h.accessCookieDebug(request)

	if debug.Count != 3 {
		t.Fatalf("expected 3 cookies, got %d", debug.Count)
	}
	if debug.Names != "gateway_session*2,ha_session" {
		t.Fatalf("unexpected cookie names summary: %q", debug.Names)
	}
	if !debug.GatewayPresent {
		t.Fatal("expected gateway cookie to be present")
	}
	if debug.GatewayCount != 2 {
		t.Fatalf("expected 2 gateway cookies, got %d", debug.GatewayCount)
	}
	if !debug.GatewayValid {
		t.Fatal("expected at least one valid gateway cookie")
	}
	if debug.GatewayExpired {
		t.Fatal("expected gateway cookie to be unexpired")
	}
	if debug.GatewayRecordIP != "203.0.113.10" {
		t.Fatalf("unexpected gateway record IP: %q", debug.GatewayRecordIP)
	}
	if strings.Contains(debug.Names, "valid-session") || strings.Contains(debug.Names, "do-not-log") {
		t.Fatalf("cookie values leaked in summary: %q", debug.Names)
	}
}

func TestAccessCookieDebugDetectsMissingGatewaySession(t *testing.T) {
	h := newTestHandlers()

	request := httptest.NewRequest(http.MethodGet, "/access", nil)
	request.AddCookie(&http.Cookie{Name: "ha_session", Value: "do-not-log"})

	debug := h.accessCookieDebug(request)

	if debug.Count != 1 {
		t.Fatalf("expected 1 cookie, got %d", debug.Count)
	}
	if debug.Names != "ha_session" {
		t.Fatalf("unexpected cookie names summary: %q", debug.Names)
	}
	if debug.GatewayPresent {
		t.Fatal("expected gateway cookie to be missing")
	}
	if debug.GatewayValid {
		t.Fatal("expected gateway cookie to be invalid")
	}
}

func newTestHandlers() Handlers {
	return Handlers{
		expirationDays: 30,
		cookieName:     "gateway_session",
		metrics: &Metrics{
			AccessPageVisits: prometheus.NewCounter(prometheus.CounterOpts{Name: "test_access_page_visits_total"}),
			AccessRequests:   prometheus.NewCounter(prometheus.CounterOpts{Name: "test_access_requests_total"}),
		},
	}
}
