package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const testPassword = "test-password"

// postUnlock issues a POST /unlock from ip with the given password. The real
// client IP is supplied via X-Gateway-Client-IP, the way the fronting Caddy
// passes it. It returns gin's resolved status (CreateTestContext bypasses the
// engine's WriteHeaderNow flush, so the recorder's own Code isn't reliable for
// body-less responses) along with the recorder for header assertions.
func postUnlock(h *Handlers, ip, pass string) (int, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/unlock", strings.NewReader("pass="+pass))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request.Header.Set("X-Gateway-Client-IP", ip)
	h.UnlockPage(c)
	return c.Writer.Status(), w
}

func TestUnlockWrongPasswordReturns401(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers()
	h.unlockPasswd = testPassword
	h.persistFile = filepath.Join(t.TempDir(), "granted.json")

	status, _ := postUnlock(&h, "203.0.113.7", "wrong")

	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password, got %d", status)
	}
}

func TestUnlockCorrectPasswordGrantsHeaderIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers()
	h.unlockPasswd = testPassword
	h.persistFile = filepath.Join(t.TempDir(), "granted.json")

	status, w := postUnlock(&h, "203.0.113.7", testPassword)

	if status != http.StatusOK {
		t.Fatalf("expected 200 on correct password, got %d", status)
	}
	if findTestGrant(&h, "203.0.113.7") == nil {
		t.Fatal("expected the header IP (real visitor) to be granted")
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "gateway_session=") {
		t.Fatalf("expected a session cookie to be set, got %q", w.Header().Get("Set-Cookie"))
	}
}

func TestUnlockLocksOutAfterRepeatedFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers() // maxLoginFailures = 3
	h.unlockPasswd = testPassword
	h.persistFile = filepath.Join(t.TempDir(), "granted.json")

	const ip = "203.0.113.7"
	for i := 0; i < 3; i++ {
		if status, _ := postUnlock(&h, ip, "wrong"); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, status)
		}
	}

	// Now locked out: even the correct password is refused with 429.
	status, w := postUnlock(&h, ip, testPassword)
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once locked out, got %d", status)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on lockout")
	}
	if findTestGrant(&h, ip) != nil {
		t.Fatal("locked-out IP must not be granted even with the correct password")
	}

	// A different IP is unaffected by the lockout.
	if status, _ := postUnlock(&h, "203.0.113.8", testPassword); status != http.StatusOK {
		t.Fatalf("expected a different IP to still unlock (200), got %d", status)
	}
}

func TestUnlockSuccessClearsFailureCount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newTestHandlers() // maxLoginFailures = 3
	h.unlockPasswd = testPassword
	h.persistFile = filepath.Join(t.TempDir(), "granted.json")

	const ip = "203.0.113.7"
	// Two failures (below threshold), a success that resets the counter, then
	// two more failures -- still below threshold, so no lockout.
	for _, pass := range []string{"wrong", "wrong", testPassword, "wrong", "wrong"} {
		_, _ = postUnlock(&h, ip, pass)
	}

	if locked, _ := h.isLockedOut(ip); locked {
		t.Fatal("expected a successful unlock to reset the failure count")
	}
}
