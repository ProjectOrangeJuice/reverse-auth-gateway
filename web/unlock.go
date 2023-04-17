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
		if p == h.UnlockPasswd {
			a := authed{IP: g.ClientIP(), Authed: time.Now().Format(time.UnixDate)}
			allowed = append(allowed, &a)
			log.Printf("Adding %v to allowed list", g.ClientIP())
		}
	}
	h.Templates.ExecuteTemplate(g.Writer, "unlock", nil)
}
