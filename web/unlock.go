package web

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) UnlockPage(g *gin.Context) {
	if g.Request.Method == http.MethodPost {
		p := g.Params.ByName("pass")
		if p == "somerandompassword" {
			a := authed{IP: r.Header.Get("X-FORWARDED-FOR"), Authed: time.Now().Format(time.UnixDate)}
			allowed = append(allowed, &a)
			log.Printf("Adding %v to allowed list", r.Header.Get("X-FORWARDED-FOR"))
		}
	}
	h.Templates.ExecuteTemplate(w, "unlock", nil)
}
