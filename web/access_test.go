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
