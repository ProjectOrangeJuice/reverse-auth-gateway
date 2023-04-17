package web

import (
	"log"

	"github.com/gin-gonic/gin"
)

type auditView struct {
	Granted []*authed
	Failed  map[string][]failedLogin
}

func (h *Handlers) AuditPage(g *gin.Context) {
	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	m := make(map[string][]failedLogin)
	h.activity.Range(func(key, value interface{}) bool {
		m[key.(string)] = value.([]failedLogin)
		return true
	})
	log.Printf("copied failed login -> %+v", m)
	view := auditView{Granted: copiedGranted, Failed: m}

	h.Templates.ExecuteTemplate(g.Writer, "audit", view)
}
