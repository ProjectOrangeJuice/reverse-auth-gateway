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
			h.setSessionCookie(g, record)
		} else {
			h.metrics.WrongPasswordCount.Inc()
			recordInterface, ok := h.activity.Load(g.ClientIP())
			var records []failedLogin
			if ok {
				records = recordInterface.([]failedLogin)
			}

			records = append(records, failedLogin{
				Password: sanitizeForLog(password),
				When:     time.Now().Format(time.UnixDate),
			})

			// Cap per-IP failed login history to prevent memory exhaustion
			if len(records) > 100 {
				records = records[len(records)-100:]
			}

			h.activity.Store(g.ClientIP(), records)
			log.Printf("Failed login from %v", g.ClientIP())
		}
	}

	if err := h.Templates.ExecuteTemplate(g.Writer, "unlock", nil); err != nil {
		log.Printf("Failed to render unlock page: %v", err)
		g.Status(http.StatusInternalServerError)
	}
}

func (h *Handlers) addGranted(ip string) (*authed, error) {
	now := time.Now()

	h.auditLock.Lock()
	if existing := h.reuseGrantedIPLocked(ip, now); existing != nil {
		h.auditLock.Unlock()
		log.Printf("Reusing existing auth session for %v", ip)
		go h.saveGranted()
		return existing, nil
	}

	record, err := newAuthed(ip, now)
	if err != nil {
		h.auditLock.Unlock()
		return nil, err
	}
	h.granted = append(h.granted, record)
	h.auditLock.Unlock()

	go handleBucket(record)
	log.Printf("Adding %v to allowed list", ip)

	go h.saveGranted()
	go h.sendUnlockNotification(ip)

	return record, nil
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
