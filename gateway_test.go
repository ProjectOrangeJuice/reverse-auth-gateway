package main

import (
	"testing"
)

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
