package web

import "github.com/gin-gonic/gin"

func (h *Handlers) AuditPage(g *gin.Context) {
	h.Templates.ExecuteTemplate(g.Writer, "audit", allowed)
}
