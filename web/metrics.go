package web

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (h *Handlers) MetricsHandler(g *gin.Context) {
	promhttp.Handler().ServeHTTP(g.Writer, g.Request)
}