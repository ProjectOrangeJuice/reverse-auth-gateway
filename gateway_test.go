package main

import (
	"net/http/httptest"
	"strings"
	"testing"

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
