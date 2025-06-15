package web

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) UnlockPage(g *gin.Context) {
	if g.Request.Method == http.MethodPost {
		rawPassword := g.Request.FormValue("pass")
		
		// Validate password input
		password, valid := validatePassword(rawPassword)
		if !valid {
			log.Printf("Invalid password format from %v", g.ClientIP())
			g.Status(http.StatusBadRequest)
			return
		}
		
		if password == h.unlockPasswd {
			h.addGranted(g.ClientIP())
		} else {
			// Record failed logins with sanitized password for security
			recordInterface, ok := h.activity.Load(g.ClientIP())
			var records []failedLogin
			if ok {
				records = recordInterface.([]failedLogin)
			}
			
			// Store sanitized password to prevent log injection
			sanitizedPass := sanitizeForLog(password)
			records = append(records, failedLogin{Password: sanitizedPass, When: time.Now().Format(time.UnixDate)})
			h.activity.Store(g.ClientIP(), records)
			log.Printf("Failed login, %v tried with password %s", g.ClientIP(), sanitizedPass)
		}
	}

	h.Templates.ExecuteTemplate(g.Writer, "unlock", nil)
}

func (h *Handlers) addGranted(ip string) *authed {
	a := authed{IP: ip, Authed: time.Now().Format(time.UnixDate), Requests: make(map[time.Time]int)}
	h.auditLock.Lock()
	h.granted = append(h.granted, &a)
	h.auditLock.Unlock()
	go handleBucket(&a)
	log.Printf("Adding %v to allowed list", ip)
	return &a
}

func handleBucket(a *authed) {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		log.Printf("Ticked for record %+v", a)
		// Get the current time truncated to the nearest hour
		now := time.Now().UTC().Truncate(time.Hour)

		// Lock the mutex to prevent concurrent access to the accessCount map
		a.recordEditLock.Lock()

		// Prune the access count for buckets older than 7 days
		for bucket := range a.Requests {
			if now.Sub(bucket) > 7*24*time.Hour {
				delete(a.Requests, bucket)
			}
		}

		// Unlock the mutex to allow concurrent access to the accessCount map
		a.recordEditLock.Unlock()
	}
}
