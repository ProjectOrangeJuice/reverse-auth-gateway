package web

import "github.com/gin-gonic/gin"

func (h *Handlers) AuditPage(g *gin.Context) {
	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()
	h.Templates.ExecuteTemplate(g.Writer, "audit", copiedGranted)
}
