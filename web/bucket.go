package web

import (
	"log"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) BucketPage(g *gin.Context) {
	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	lookup := g.Query("ip")
	var record *authed
	log.Printf("Looking up bucket data for %s", lookup)
	for _, a := range copiedGranted {
		if a.IP == lookup {
			record = a
		}
	}

	h.Templates.ExecuteTemplate(g.Writer, "buckets", record)
}
