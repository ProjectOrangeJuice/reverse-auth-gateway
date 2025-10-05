package web

import (
	"encoding/json"
	"html/template"
	"log"
	"os"
	"regexp"
	"strconv"
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

	auditLock      sync.Mutex // Not concerned for performance
	granted        []*authed
	activity       sync.Map
	metrics        *Metrics
	persistFile    string
	expirationDays int
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
	AuthedTime      time.Time         `json:"authed_time"`
	Authed          string            `json:"-"` // Keep for backward compatibility, don't persist
	LastAccess      string            `json:"last_access"`
	DomainsAccessed []string          `json:"domains_accessed"`
	Requests        map[time.Time]int `json:"requests"`

	recordEditLock sync.Mutex `json:"-"`
}

type persistedAuthed struct {
	IP              string            `json:"ip"`
	AuthedTime      time.Time         `json:"authed_time"`
	LastAccess      string            `json:"last_access"`
	DomainsAccessed []string          `json:"domains_accessed"`
	Requests        map[time.Time]int `json:"requests"`
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
	persistFile := os.Getenv("PERSIST_FILE")
	if persistFile == "" {
		persistFile = "granted_ips.json"
	}

	expirationDays := 30 // default
	if expStr := os.Getenv("IP_EXPIRATION_DAYS"); expStr != "" {
		if days, err := strconv.Atoi(expStr); err == nil && days > 0 {
			expirationDays = days
		} else {
			log.Printf("Invalid IP_EXPIRATION_DAYS value '%s', using default of 30 days", expStr)
		}
	}

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

	h := Handlers{
		Templates:      templates,
		unlockPasswd:   unlockPasswd,
		metrics:        metrics,
		persistFile:    persistFile,
		expirationDays: expirationDays,
	}

	// Load persisted IPs on startup
	h.loadGranted()

	// Start background cleanup goroutine
	go h.cleanupExpiredIPs()

	return h
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

// loadGranted reads persisted IPs from file on startup
func (h *Handlers) loadGranted() {
	data, err := os.ReadFile(h.persistFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No persist file found at %s, starting fresh", h.persistFile)
		} else {
			log.Printf("Error reading persist file: %v", err)
		}
		return
	}

	var persisted []persistedAuthed
	if err := json.Unmarshal(data, &persisted); err != nil {
		log.Printf("Error unmarshaling persist file: %v", err)
		return
	}

	now := time.Now()
	expirationDuration := time.Duration(h.expirationDays) * 24 * time.Hour

	h.auditLock.Lock()
	defer h.auditLock.Unlock()

	for _, p := range persisted {
		// Skip expired entries
		if now.Sub(p.AuthedTime) > expirationDuration {
			log.Printf("Skipping expired IP %s (authed %v)", p.IP, p.AuthedTime)
			continue
		}

		a := &authed{
			IP:              p.IP,
			AuthedTime:      p.AuthedTime,
			Authed:          p.AuthedTime.Format(time.UnixDate),
			LastAccess:      p.LastAccess,
			DomainsAccessed: p.DomainsAccessed,
			Requests:        p.Requests,
		}
		if a.Requests == nil {
			a.Requests = make(map[time.Time]int)
		}
		h.granted = append(h.granted, a)
		go handleBucket(a)
		log.Printf("Restored IP %s from persist file (authed %v)", p.IP, p.AuthedTime)
	}

	log.Printf("Loaded %d IP(s) from persist file", len(h.granted))
}

// saveGranted writes current granted IPs to file
func (h *Handlers) saveGranted() {
	h.auditLock.Lock()
	persisted := make([]persistedAuthed, 0, len(h.granted))
	for _, a := range h.granted {
		a.recordEditLock.Lock()
		persisted = append(persisted, persistedAuthed{
			IP:              a.IP,
			AuthedTime:      a.AuthedTime,
			LastAccess:      a.LastAccess,
			DomainsAccessed: a.DomainsAccessed,
			Requests:        a.Requests,
		})
		a.recordEditLock.Unlock()
	}
	h.auditLock.Unlock()

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		log.Printf("Error marshaling granted IPs: %v", err)
		return
	}

	if err := os.WriteFile(h.persistFile, data, 0600); err != nil {
		log.Printf("Error writing persist file: %v", err)
		return
	}

	log.Printf("Saved %d IP(s) to persist file", len(persisted))
}

// cleanupExpiredIPs runs in background to remove expired IPs
func (h *Handlers) cleanupExpiredIPs() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		expirationDuration := time.Duration(h.expirationDays) * 24 * time.Hour

		h.auditLock.Lock()
		newGranted := make([]*authed, 0, len(h.granted))
		removed := 0

		for _, a := range h.granted {
			if now.Sub(a.AuthedTime) > expirationDuration {
				log.Printf("Removing expired IP %s (authed %v)", a.IP, a.AuthedTime)
				removed++
			} else {
				newGranted = append(newGranted, a)
			}
		}

		h.granted = newGranted
		h.auditLock.Unlock()

		if removed > 0 {
			log.Printf("Cleanup: removed %d expired IP(s)", removed)
			h.saveGranted()
		}
	}
}

// isExpired checks if an IP has expired
func (h *Handlers) isExpired(a *authed) bool {
	expirationDuration := time.Duration(h.expirationDays) * 24 * time.Hour
	return time.Since(a.AuthedTime) > expirationDuration
}
