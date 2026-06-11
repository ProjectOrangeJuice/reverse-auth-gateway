package web

import (
	"log"
	"time"
)

// loginAttempt tracks failed unlock attempts for a single client IP so repeated
// guesses can be locked out. Behind Cloudflare the only throttle on the cloud
// path is per-IP, so this is the primary brute-force defense against a single
// shared password.
type loginAttempt struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// isLockedOut reports whether the IP is currently locked out and, if so, how
// long remains.
func (h *Handlers) isLockedOut(ip string) (bool, time.Duration) {
	h.loginLock.Lock()
	defer h.loginLock.Unlock()

	a := h.loginAttempts[ip]
	if a == nil {
		return false, 0
	}
	if remaining := time.Until(a.lockedUntil); remaining > 0 {
		return true, remaining
	}
	return false, 0
}

// registerFailedLogin records a failed unlock for the IP and locks it out once
// the failure threshold is reached.
func (h *Handlers) registerFailedLogin(ip string) {
	h.loginLock.Lock()
	defer h.loginLock.Unlock()

	if h.loginAttempts == nil {
		h.loginAttempts = make(map[string]*loginAttempt)
	}

	now := time.Now()
	a := h.loginAttempts[ip]
	if a == nil {
		a = &loginAttempt{}
		h.loginAttempts[ip] = a
	}
	a.lastSeen = now
	a.failures++

	if h.maxLoginFailures > 0 && a.failures >= h.maxLoginFailures {
		a.lockedUntil = now.Add(h.lockoutDuration)
		a.failures = 0
		log.Printf("Locking out %s until %v after repeated failed logins", ip, a.lockedUntil)
	}
}

// clearLoginAttempts drops any failure/lockout state for the IP, called after a
// successful unlock.
func (h *Handlers) clearLoginAttempts(ip string) {
	h.loginLock.Lock()
	defer h.loginLock.Unlock()

	delete(h.loginAttempts, ip)
}

// pruneLoginAttempts removes stale entries so the map can't grow unbounded from
// a churn of distinct failing IPs.
func (h *Handlers) pruneLoginAttempts(now time.Time) {
	h.loginLock.Lock()
	defer h.loginLock.Unlock()

	for ip, a := range h.loginAttempts {
		if now.After(a.lockedUntil) && now.Sub(a.lastSeen) > time.Hour {
			delete(h.loginAttempts, ip)
		}
	}
}
