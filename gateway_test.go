package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/gin-gonic/gin"
)

func TestSafeGinLogFormatterDropsQuery(t *testing.T) {
	request := httptest.NewRequest("GET", "/access?access_token=secret-token", nil)
	output := safeGinLogFormatter(gin.LogFormatterParams{
		Request: request,
		Method:  request.Method,
		Path:    request.URL.RequestURI(),
	})

	if strings.Contains(output, "secret-token") || strings.Contains(output, "access_token") {
		t.Fatalf("expected query to be redacted from log output, got %q", output)
	}
	if !strings.Contains(output, `"/access"`) {
		t.Fatalf("expected path to remain in log output, got %q", output)
	}
}

func TestSafeGinLogFormatterUsesClientIPHeader(t *testing.T) {
	// Simulate a request arriving from a Railway edge with the real client
	// IP injected by Caddy via the custom header (the same mechanism used
	// internally for grants and access checks).
	req := httptest.NewRequest("GET", "/access", nil)
	req.RemoteAddr = "79.127.178.82:54321" // the edge we do NOT want to log
	req.Header.Set("X-Gateway-Client-IP", "203.0.113.77")

	output := safeGinLogFormatter(gin.LogFormatterParams{
		Request:  req,
		Method:   req.Method,
		Path:     req.URL.RequestURI(),
		ClientIP: "79.127.178.82", // what Gin would normally compute
	})

	if !strings.Contains(output, "203.0.113.77") {
		t.Fatalf("expected real client IP from header in log, got %q", output)
	}
	if strings.Contains(output, "79.127.178.82") {
		t.Fatalf("did not expect edge IP to appear in log output, got %q", output)
	}
	if !strings.Contains(output, `"/access"`) {
		t.Fatalf("expected path to remain in log output, got %q", output)
	}
}

func TestGetTrustedProxiesAcceptsIPsAndCIDRs(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1, 100.64.0.0/10, invalid")

	proxies := getTrustedProxies()
	if len(proxies) != 2 {
		t.Fatalf("expected two valid trusted proxies, got %#v", proxies)
	}
	if proxies[0] != "10.0.0.1" || proxies[1] != "100.64.0.0/10" {
		t.Fatalf("unexpected trusted proxies: %#v", proxies)
	}
}

func TestGetTrustedProxiesDefaultsToPrivateRanges(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")

	proxies := getTrustedProxies()
	if len(proxies) == 0 {
		t.Fatal("expected default trusted proxy ranges")
	}
	if proxies[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected first default proxy range: %#v", proxies)
	}
}

func TestListenAddrDefaultAndValidation(t *testing.T) {
	t.Setenv("PORT", "")
	addr, err := listenAddr()
	if err != nil {
		t.Fatalf("default port: %v", err)
	}
	if addr != ":9090" {
		t.Fatalf("expected :9090, got %q", addr)
	}

	t.Setenv("PORT", "8080")
	addr, err = listenAddr()
	if err != nil {
		t.Fatalf("valid port: %v", err)
	}
	if addr != ":8080" {
		t.Fatalf("expected :8080, got %q", addr)
	}

	for _, bad := range []string{"0", "-1", "65536", "abc", "80abc"} {
		t.Setenv("PORT", bad)
		if _, err := listenAddr(); err == nil {
			t.Fatalf("expected error for PORT=%q", bad)
		}
	}
}

func TestHealthHandlerOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/health", nil)
	healthHandler(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(securityHeaders)
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff, headers=%v", w.Header())
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing frame deny")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("expected frame-ancestors in CSP, got %q", w.Header().Get("Content-Security-Policy"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control no-store")
	}
}

func TestLimitByClientIPKeysOnHeaderNotRemoteAddr(t *testing.T) {
	gin.SetMode(gin.TestMode)

	lmt := tollbooth.NewLimiter(1, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lmt.SetBurst(1)

	router := gin.New()
	router.GET("/unlock", limitByClientIP(lmt, "X-Gateway-Client-IP"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	hit := func(remote, header string) int {
		req := httptest.NewRequest(http.MethodGet, "/unlock", nil)
		req.RemoteAddr = remote
		if header != "" {
			req.Header.Set("X-Gateway-Client-IP", header)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := hit("10.0.0.1:12345", "203.0.113.10"); code != http.StatusOK {
		t.Fatalf("first visitor: expected 200, got %d", code)
	}
	if code := hit("10.0.0.1:12345", "203.0.113.10"); code != http.StatusTooManyRequests {
		t.Fatalf("same visitor: expected 429, got %d", code)
	}
	if code := hit("10.0.0.1:12345", "203.0.113.99"); code != http.StatusOK {
		t.Fatalf("different visitor sharing proxy hop: expected 200, got %d", code)
	}
}
