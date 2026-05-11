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
			record, err := h.addGranted(g.ClientIP())
			if err != nil {
				log.Printf("Failed to create auth session for %v: %v", g.ClientIP(), err)
				g.Status(http.StatusInternalServerError)
				return
			}
			h.setSessionCookie(g, record)
		} else {
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
	h.granted = append(h.granted, record)
	h.grantedLock.Unlock()

	log.Printf("Adding %v to allowed list", ip)

	go h.saveGranted()
	go h.sendUnlockNotification(ip)

	return record, nil
}
