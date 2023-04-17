package web

import "net/http"

func (h *Handlers) AuditPage(w http.ResponseWriter, r *http.Request) {
	h.Templates.ExecuteTemplate(w, "audit", allowed)
}
