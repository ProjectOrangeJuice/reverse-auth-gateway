package main

import (
	"fmt"
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

var defaultTrustedProxies = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"127.0.0.1/8",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	// Cloudflare IPv4 ranges - https://www.cloudflare.com/ips-v4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Cloudflare IPv6 ranges - https://www.cloudflare.com/ips-v6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func main() {
	configureGinMode()

	handlers := web.SetupHandlers()
	router := newRouter()

	trustedProxies := getTrustedProxies()
	if len(trustedProxies) > 0 {
		if err := router.SetTrustedProxies(trustedProxies); err != nil {
			log.Fatalf("invalid TRUSTED_PROXIES configuration: %v", err)
		}
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
	// metricsLim := tollbooth.NewLimiter(1, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

	router.POST("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/access", tollbooth_gin.LimitHandler(accessLim), handlers.AccessPage)
	// router.GET("/metrics", tollbooth_gin.LimitHandler(metricsLim), handlers.MetricsHandler)
	router.Static("/css", "web/src/css")

	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	server := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           router,
	}

	log.Fatal(server.ListenAndServe())
}

func configureGinMode() {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
}

func newRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.LoggerWithFormatter(safeGinLogFormatter), gin.Recovery())
	return router
}

func safeGinLogFormatter(param gin.LogFormatterParams) string {
	path := "/"
	if param.Request != nil && param.Request.URL != nil && param.Request.URL.EscapedPath() != "" {
		path = param.Request.URL.EscapedPath()
	}

	return fmt.Sprintf("[GIN] %v | %3d | %13v | %15s | %-7s %q\n",
		param.TimeStamp.Format("2006/01/02 - 15:04:05"),
		param.StatusCode,
		param.Latency,
		param.ClientIP,
		param.Method,
		path,
	)
}

func getTrustedProxies() []string {
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies == "" {
		return append([]string(nil), defaultTrustedProxies...)
	}
	var valid []string
	for _, p := range strings.Split(proxies, ",") {
		p = strings.TrimSpace(p)
		if isTrustedProxyValue(p) {
			valid = append(valid, p)
		} else {
			log.Printf("Ignoring invalid trusted proxy value: %q", p)
		}
	}
	return valid
}

func isTrustedProxyValue(proxy string) bool {
	if net.ParseIP(proxy) != nil {
		return true
	}

	_, _, err := net.ParseCIDR(proxy)
	return err == nil
}
