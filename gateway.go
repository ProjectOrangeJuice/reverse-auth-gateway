package main

import (
	"gateway/web"
	"log"
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

	// Create a new limiter that allows 5 requests per second with a burst limit of 5.
	lim := tollbooth.NewLimiter(5, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lim.SetBurst(5)

	router.POST("/unlock", tollbooth_gin.LimitHandler(lim), handlers.UnlockPage)
	router.GET("/unlock", handlers.UnlockPage)
	router.GET("/access", handlers.AccessPage)
	router.GET("/audit", handlers.AuditPage)
	router.GET("/buckets", handlers.BucketPage)
	router.Static("/css", "web/src/css")

	server := &http.Server{
		Addr:              ":9090",
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           router,
	}

	log.Fatal(server.ListenAndServe())
}

func getTrustedProxies() []string {
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies == "" {
		return nil
	}
	return strings.Split(proxies, ",")
}
