package web

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) BucketPage(g *gin.Context) {
	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	rawLookup := g.Query("ip")
	lookup, valid := validateQueryParam(rawLookup)
	if !valid {
		log.Printf("Invalid IP parameter in bucket request from %v", g.ClientIP())
		g.Status(http.StatusBadRequest)
		return
	}
	
	var record *authed
	log.Printf("Looking up bucket data for %s", sanitizeForLog(lookup))
	for _, a := range copiedGranted {
		if a.IP == lookup {
			record = a
		}
	}

	h.Templates.ExecuteTemplate(g.Writer, "buckets", record)
}
