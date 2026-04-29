package web

import (
	"log"
	"net/http"

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
		if failures, ok := value.([]failedLogin); ok {
			m[key.(string)] = failures
		}
		return true
	})

	view := auditView{Granted: copiedGranted, Failed: m}
	if err := h.Templates.ExecuteTemplate(g.Writer, "audit", view); err != nil {
		log.Printf("Failed to render audit page: %v", err)
		g.Status(http.StatusInternalServerError)
	}
}
