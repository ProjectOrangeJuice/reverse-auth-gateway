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

// defaultTrustedProxies is the set of hops directly in front of the gateway.
// The real client IP no longer comes from walking X-Forwarded-For across
// Cloudflare; the fronting Caddy resolves it (from CF-Connecting-IP) and passes
// it explicitly via CLIENT_IP_HEADER. So we only trust the immediate private /
// Tailscale hop here. The Cloudflare ranges were removed deliberately: trusting
// them let a shared PoP egress IP masquerade as the client.
var defaultTrustedProxies = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"127.0.0.1/8",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
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

	// Coarse throttle on the auth endpoints. The real brute-force defense is the
	// per-IP lockout in the web package (keyed on the resolved client IP); this
	// just smooths bursts.
	authLim := tollbooth.NewLimiter(2, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	authLim.SetBurst(5)

	// Higher limit for access checks (nginx calls this per request)
	accessLim := tollbooth.NewLimiter(50, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

	router.POST("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/unlock", tollbooth_gin.LimitHandler(authLim), handlers.UnlockPage)
	router.GET("/access", tollbooth_gin.LimitHandler(accessLim), handlers.AccessPage)
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
	// Logger removed to reduce per-request allocations and log volume.
	// Key events (grants, rejects, expirations) are still logged explicitly.
	router.Use(gin.Recovery())
	return router
}

func safeGinLogFormatter(param gin.LogFormatterParams) string {
	path := "/"
	if param.Request != nil && param.Request.URL != nil && param.Request.URL.EscapedPath() != "" {
		path = param.Request.URL.EscapedPath()
	}

	// Prefer the real client IP (from CLIENT_IP_HEADER) so logs show the
	// per-visitor address rather than a Railway edge / proxy. Falls back to
	// Gin's computed ClientIP (which may be the direct peer when the header
	// is absent or invalid). The same preference+validation logic lives in
	// web.RealClientIP and is used by the unlock/access handlers.
	clientIP := param.ClientIP
	if param.Request != nil {
		hdr := os.Getenv("CLIENT_IP_HEADER")
		if hdr == "" {
			hdr = "X-Gateway-Client-IP"
		}
		if real := web.RealClientIP(param.Request, hdr); real != "" {
			clientIP = real
		}
	}

	return fmt.Sprintf("[GIN] %v | %3d | %13v | %15s | %-7s %q\n",
		param.TimeStamp.Format("2006/01/02 - 15:04:05"),
		param.StatusCode,
		param.Latency,
		clientIP,
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
