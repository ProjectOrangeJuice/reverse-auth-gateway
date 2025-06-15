package web

import (
	"html/template"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Handlers struct {
	Templates    *template.Template
	unlockPasswd string

	auditLock sync.Mutex // Not concerned for performance
	granted   []*authed
	activity  sync.Map
	metrics   *Metrics
}

type Metrics struct {
	AccessPageVisits     prometheus.Counter
	WrongPasswordCount   prometheus.Counter
	CorrectPasswordCount prometheus.Counter
	AccessRequests       prometheus.Counter
	AccessDetails        []AccessRequest
	lock                sync.RWMutex
}

type AccessRequest struct {
	IP        string
	Timestamp time.Time
	UserAgent string
	Host      string
	Method    string
}

type authed struct {
	IP              string
	Authed          string
	LastAccess      string
	DomainsAccessed []string

	Requests map[time.Time]int

	recordEditLock sync.Mutex
}

type failedLogin struct {
	Password string
	When     string
}

func SetupHandlers() Handlers {
	templates, err := template.ParseGlob("web/src/*.html")
	if err != nil {
		log.Fatalf("%s\n", err)
		return Handlers{}
	}

	unlockPasswd := os.Getenv("GATEWAY_PASSWORD")

	metrics := &Metrics{
		AccessPageVisits: promauto.NewCounter(prometheus.CounterOpts{
			Name: "gateway_access_page_visits_total",
			Help: "The total number of visits to the access page",
		}),
		WrongPasswordCount: promauto.NewCounter(prometheus.CounterOpts{
			Name: "gateway_wrong_password_attempts_total",
			Help: "The total number of wrong password attempts",
		}),
		CorrectPasswordCount: promauto.NewCounter(prometheus.CounterOpts{
			Name: "gateway_correct_password_attempts_total",
			Help: "The total number of correct password attempts",
		}),
		AccessRequests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "gateway_access_requests_total",
			Help: "The total number of access requests with details",
		}),
	}

	return Handlers{
		Templates:    templates, 
		unlockPasswd: unlockPasswd,
		metrics:      metrics,
	}
}

// Input validation functions
func validatePassword(password string) (string, bool) {
	// Check for null bytes and control characters that could cause issues
	if strings.Contains(password, "\x00") {
		return "", false
	}
	
	// Check for valid UTF-8
	if !utf8.ValidString(password) {
		return "", false
	}
	
	// Limit password length to prevent memory exhaustion attacks
	if len(password) > 1000 {
		return "", false
	}
	
	// Trim whitespace
	password = strings.TrimSpace(password)
	
	// Don't allow empty passwords after trimming
	if password == "" {
		return "", false
	}
	
	return password, true
}

func sanitizeForLog(input string) string {
	// Remove control characters and null bytes for safe logging
	re := regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
	sanitized := re.ReplaceAllString(input, "")
	
	// Limit length for logs
	if len(sanitized) > 50 {
		sanitized = sanitized[:47] + "..."
	}
	
	return sanitized
}

func validateQueryParam(param string) (string, bool) {
	// Check for valid UTF-8
	if !utf8.ValidString(param) {
		return "", false
	}
	
	// Check for null bytes
	if strings.Contains(param, "\x00") {
		return "", false
	}
	
	// Limit length
	if len(param) > 100 {
		return "", false
	}
	
	// Trim whitespace
	param = strings.TrimSpace(param)
	
	return param, true
}
