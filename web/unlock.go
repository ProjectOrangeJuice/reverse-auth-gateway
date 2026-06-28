package web

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) UnlockPage(g *gin.Context) {
	if g.Request.Method == http.MethodPost {
		ip := h.clientIP(g)

		if locked, retryIn := h.isLockedOut(ip); locked {
			log.Printf("Rejecting login from locked-out IP %v (%ds remaining)", ip, int(retryIn.Seconds()))
			g.Header("Retry-After", strconv.Itoa(int(retryIn.Seconds())+1))
			g.Status(http.StatusTooManyRequests)
			return
		}

		rawPassword := g.Request.FormValue("pass")

		password, valid := validatePassword(rawPassword)
		if !valid {
			log.Printf("Invalid password format from %v", ip)
			g.Status(http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(password), []byte(h.unlockPasswd)) == 1 {
			record, err := h.addGranted(ip)
			if err != nil {
				log.Printf("Failed to create auth session for %v: %v", ip, err)
				g.Status(http.StatusInternalServerError)
				return
			}
			h.clearLoginAttempts(ip)
			h.setSessionCookie(g, record)
		} else {
			h.registerFailedLogin(ip)
			log.Printf("Failed login from %v", ip)
			// Return 401 (not 200) so a failed unlock is distinguishable in
			// access logs; the page still renders below for the user.
			g.Status(http.StatusUnauthorized)
		}
	}

	if err := h.Templates.ExecuteTemplate(g.Writer, "unlock", nil); err != nil {
		log.Printf("Failed to render unlock page: %v", err)
		g.Status(http.StatusInternalServerError)
	}
}

func (h *Handlers) addGranted(ip string) (*authed, error) {
	now := time.Now()

	h.grantedLock.Lock()
	if existing := h.reuseGrantedIPLocked(ip, now); existing != nil {
		h.grantedLock.Unlock()
		log.Printf("Reusing existing auth session for %v", ip)
		go h.saveGranted()
		return existing, nil
	}

	record, err := newAuthed(ip, now)
	if err != nil {
		h.grantedLock.Unlock()
		return nil, err
	}
	h.granted[ip] = record
	h.grantedLock.Unlock()

	log.Printf("Adding %v to allowed list", ip)

	go h.saveGranted()
	go h.sendUnlockNotification(ip)

	return record, nil
}
