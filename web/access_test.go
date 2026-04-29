package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestAddGrantedReusesExistingSessionForIP(t *testing.T) {
	h := newTestHandlers()
	h.persistFile = filepath.Join(t.TempDir(), "missing", "granted.json")

	first, err := h.addGranted("203.0.113.10")
	if err != nil {
		t.Fatalf("first addGranted failed: %v", err)
	}
	firstSession := first.Session
	firstAuthedAt := first.AuthedTime

	time.Sleep(time.Millisecond)

	second, err := h.addGranted("203.0.113.10")
	if err != nil {
		t.Fatalf("second addGranted failed: %v", err)
	}

	if second != first {
		t.Fatal("expected repeat grant to reuse existing record")
	}
	if second.Session != firstSession {
		t.Fatalf("expected session %q to be reused, got %q", firstSession, second.Session)
	}
	if len(h.granted) != 1 {
		t.Fatalf("expected one granted record, got %d", len(h.granted))
	}
	if !second.AuthedTime.After(firstAuthedAt) {
		t.Fatalf("expected auth timestamp to be refreshed, first %v second %v", firstAuthedAt, second.AuthedTime)
	}
}

func TestLoadGrantedDedupesByIPAndPreservesFirstSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	firstAuthedAt := now.Add(-2 * time.Hour)
	secondAuthedAt := now.Add(-1 * time.Hour)
	otherAuthedAt := now

	persisted := []persistedAuthed{
		{
			IP:              "203.0.113.10",
			AuthedTime:      firstAuthedAt,
			Session:         "first-session",
			LastAccess:      "first access",
			DomainsAccessed: []string{"home.harriso.co.uk"},
			Requests:        map[time.Time]int{firstAuthedAt: 2},
		},
		{
			IP:              "203.0.113.10",
			AuthedTime:      secondAuthedAt,
			Session:         "second-session",
			LastAccess:      "second access",
			DomainsAccessed: []string{"home.harriso.co.uk", "bit.harriso.co.uk"},
			Requests:        map[time.Time]int{secondAuthedAt: 3},
		},
		{
			IP:         "198.51.100.20",
			AuthedTime: otherAuthedAt,
			Session:    "other-session",
			Requests:   map[time.Time]int{otherAuthedAt: 1},
		},
	}

	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal persisted grants: %v", err)
	}
	persistFile := filepath.Join(t.TempDir(), "granted.json")
	if err := os.WriteFile(persistFile, data, 0600); err != nil {
		t.Fatalf("write persisted grants: %v", err)
	}

	h := newTestHandlers()
	h.persistFile = persistFile

	h.loadGranted()

	if len(h.granted) != 2 {
		t.Fatalf("expected two granted records after dedupe, got %d", len(h.granted))
	}

	deduped := findTestGrant(&h, "203.0.113.10")
	if deduped == nil {
		t.Fatal("expected deduped grant for 203.0.113.10")
	}
	if deduped.Session != "first-session" {
		t.Fatalf("expected first session to be preserved, got %q", deduped.Session)
	}
	if !deduped.AuthedTime.Equal(secondAuthedAt) {
		t.Fatalf("expected newest auth time to be retained, got %v", deduped.AuthedTime)
	}
	if len(deduped.DomainsAccessed) != 2 {
		t.Fatalf("expected merged domains, got %#v", deduped.DomainsAccessed)
	}
	if deduped.Requests[firstAuthedAt] != 2 || deduped.Requests[secondAuthedAt] != 3 {
		t.Fatalf("expected merged request buckets, got %#v", deduped.Requests)
	}

	savedData, err := os.ReadFile(persistFile)
	if err != nil {
		t.Fatalf("read cleaned persist file: %v", err)
	}
	var saved []persistedAuthed
	if err := json.Unmarshal(savedData, &saved); err != nil {
		t.Fatalf("unmarshal cleaned persist file: %v", err)
	}
	if len(saved) != 2 {
		t.Fatalf("expected cleaned persist file to have two records, got %d", len(saved))
	}
}

func findTestGrant(h *Handlers, ip string) *authed {
	for _, grant := range h.granted {
		if grant.IP == ip {
			return grant
		}
	}
	return nil
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
