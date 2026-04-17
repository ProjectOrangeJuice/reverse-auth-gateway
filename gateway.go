package main

import (
	"gateway/web"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/didip/tollbooth_gin"
	"github.com/gin-gonic/gin"
)

func main() {
	handlers := web.SetupHandlers()
	router := gin.Default()

	trustedProxies := getTrustedProxies()
	if len(trustedProxies) > 0 {
		router.SetTrustedProxies(trustedProxies)
	}

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")
		c.Next()
	})

	// 5 req/sec for auth endpoints
	authLim := tollbooth.NewLimiter(5, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	authLim.SetBurst(5)

	// Higher limit for access checks (nginx calls this per request)
	accessLim := tollbooth.NewLimiter(50, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

	// Low limit for metrics scraping
	metricsLim := tollbooth.NewLimiter(1, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

	router.POST("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/access", tollbooth_gin.LimitHandler(accessLim), handlers.AccessPage)
	router.GET("/metrics", tollbooth_gin.LimitHandler(metricsLim), handlers.MetricsHandler)
	router.Static("/css", "web/src/css")

	server := &http.Server{
		Addr:              ":9090",
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           router,
	}

	log.Fatal(server.ListenAndServe())
}

func getTrustedProxies() []string {
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies == "" {
		return nil
	}
	var valid []string
	for _, p := range strings.Split(proxies, ",") {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil {
			valid = append(valid, p)
		} else {
			log.Printf("Ignoring invalid trusted proxy IP: %q", p)
		}
	}
	return valid
}
