package web

import (
	"crypto/subtle"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) UnlockPage(g *gin.Context) {
	if g.Request.Method == http.MethodPost {
		rawPassword := g.Request.FormValue("pass")

		password, valid := validatePassword(rawPassword)
		if !valid {
			log.Printf("Invalid password format from %v", g.ClientIP())
			g.Status(http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(password), []byte(h.unlockPasswd)) == 1 {
			h.metrics.CorrectPasswordCount.Inc()
			record, err := h.addGranted(g.ClientIP())
			if err != nil {
				log.Printf("Failed to create auth session for %v: %v", g.ClientIP(), err)
				g.Status(http.StatusInternalServerError)
				return
			}
			g.SetSameSite(http.SameSiteLaxMode)
			g.SetCookie(h.cookieName, record.Session, h.cookieMaxAgeSeconds(), "/", h.cookieDomain, true, true)
		} else {
			h.metrics.WrongPasswordCount.Inc()
			recordInterface, ok := h.activity.Load(g.ClientIP())
			var records []failedLogin
			if ok {
				records = recordInterface.([]failedLogin)
			}

			sanitizedPass := sanitizeForLog(password)
			records = append(records, failedLogin{Password: sanitizedPass, When: time.Now().Format(time.UnixDate)})

			// Cap per-IP failed login history to prevent memory exhaustion
			if len(records) > 100 {
				records = records[len(records)-100:]
			}

			h.activity.Store(g.ClientIP(), records)
			log.Printf("Failed login, %v tried with password %s", g.ClientIP(), sanitizedPass)
		}
	}

	h.Templates.ExecuteTemplate(g.Writer, "unlock", nil)
}

func (h *Handlers) addGranted(ip string) (*authed, error) {
	now := time.Now()
	session, err := generateSession()
	if err != nil {
		return nil, err
	}
	a := authed{
		IP:         ip,
		AuthedTime: now,
		Session:    session,
		Authed:     now.Format(time.UnixDate),
		Requests:   make(map[time.Time]int),
	}
	h.auditLock.Lock()
	h.granted = append(h.granted, &a)
	h.auditLock.Unlock()
	go handleBucket(&a)
	log.Printf("Adding %v to allowed list", ip)

	go h.saveGranted()
	go h.sendUnlockNotification(ip)

	return &a, nil
}

func handleBucket(a *authed) {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		log.Printf("Hourly cleanup tick for IP %s", a.IP)
		now := time.Now().UTC().Truncate(time.Hour)

		a.recordEditLock.Lock()
		for bucket := range a.Requests {
			if now.Sub(bucket) > 7*24*time.Hour {
				delete(a.Requests, bucket)
			}
		}
		a.recordEditLock.Unlock()
	}
}
