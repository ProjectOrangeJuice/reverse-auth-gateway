package main

import (
	"gateway/web"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	handlers := web.SetupHandlers()
	router := gin.Default()

	router.POST("/unlock", handlers.UnlockPage)
	router.GET("/unlock", handlers.UnlockPage)
	router.GET("/access", handlers.AccessPage)
	router.GET("/audit", handlers.AuditPage)
	log.Fatal(http.ListenAndServe(":9090", router))
}
