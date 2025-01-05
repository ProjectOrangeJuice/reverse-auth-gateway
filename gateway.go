package main

import (
	"gateway/web"
	"log"
	"net/http"
	"time"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/didip/tollbooth_gin"
	"github.com/gin-gonic/gin"
)

func main() {
	handlers := web.SetupHandlers()
	router := gin.Default()
	// Create a new limiter that allows 5 requests per second with a burst limit of 5.
	lim := tollbooth.NewLimiter(5, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lim.SetBurst(5)

	router.POST("/unlock", tollbooth_gin.LimitHandler(lim), handlers.UnlockPage)
	router.GET("/unlock", handlers.UnlockPage)
	router.GET("/access", handlers.AccessPage)
	router.GET("/audit", handlers.AuditPage)
	router.GET("/buckets", handlers.BucketPage)
	router.Static("/css", "web/src/css")
	log.Fatal(http.ListenAndServe(":9090", router))
}
