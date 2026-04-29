package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	cookieDomain   string
	cookieName     string

	notifyEmail string
	smtpHost    string
	smtpPort    string
	smtpUser    string
	smtpPass    string
}

type Metrics struct {
	AccessPageVisits     prometheus.Counter
	WrongPasswordCount   prometheus.Counter
	CorrectPasswordCount prometheus.Counter
	AccessRequests       prometheus.Counter
	AccessDetails        []AccessRequest
	lock                 sync.RWMutex
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
	Session         string            `json:"session"`
	Authed          string            `json:"-"` // Keep for backward compatibility, don't persist
	LastAccess      string            `json:"last_access"`
	DomainsAccessed []string          `json:"domains_accessed"`
	Requests        map[time.Time]int `json:"requests"`

	recordEditLock sync.Mutex `json:"-"`
}

type persistedAuthed struct {
	IP              string            `json:"ip"`
	AuthedTime      time.Time         `json:"authed_time"`
	Session         string            `json:"session"`
	LastAccess      string            `json:"last_access"`
	DomainsAccessed []string          `json:"domains_accessed"`
	Requests        map[time.Time]int `json:"requests"`
}

type failedLogin struct {
	Password string
	When     string
}

var errMissingIP = errors.New("missing IP")

func SetupHandlers() *Handlers {
	templates, err := template.ParseGlob("web/src/*.html")
	if err != nil {
		log.Fatalf("%s\n", err)
		return &Handlers{}
	}

	unlockPasswd := os.Getenv("GATEWAY_PASSWORD")
	persistFile := os.Getenv("PERSIST_FILE")
	if persistFile == "" {
		persistFile = "granted_ips.json"
	}
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	cookieName := os.Getenv("COOKIE_NAME")
	if cookieName == "" {
		cookieName = "gateway_session"
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

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	notifyEmail := os.Getenv("NOTIFY_EMAIL")

	h := Handlers{
		Templates:      templates,
		unlockPasswd:   unlockPasswd,
		metrics:        metrics,
		persistFile:    persistFile,
		expirationDays: expirationDays,
		cookieDomain:   cookieDomain,
		cookieName:     cookieName,
		notifyEmail:    notifyEmail,
		smtpHost:       smtpHost,
		smtpPort:       smtpPort,
		smtpUser:       smtpUser,
		smtpPass:       smtpPass,
	}

	// Load persisted IPs on startup
	h.loadGranted()

	// Start background cleanup goroutine
	go h.cleanupExpiredIPs()

	return &h
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

func newAuthed(ip string, authedAt time.Time) (*authed, error) {
	session, err := generateSession()
	if err != nil {
		return nil, err
	}

	return &authed{
		IP:         ip,
		AuthedTime: authedAt,
		Session:    session,
		Authed:     authedAt.Format(time.UnixDate),
		Requests:   make(map[time.Time]int),
	}, nil
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
	expirationDuration := h.expirationDuration()
	byIP := make(map[string]*authed, len(persisted))
	loaded := make([]*authed, 0, len(persisted))
	expiredCount := 0
	duplicateCount := 0
	repairedCount := 0
	invalidCount := 0

	for _, p := range persisted {
		if now.Sub(p.AuthedTime) > expirationDuration {
			log.Printf("Skipping expired IP %s (authed %v)", p.IP, p.AuthedTime)
			expiredCount++
			continue
		}

		a, repaired, err := authedFromPersisted(p)
		if err != nil {
			log.Printf("Skipping persisted IP %s: %v", p.IP, err)
			invalidCount++
			continue
		}

		if existing := byIP[a.IP]; existing != nil {
			mergeAuthRecords(existing, a)
			duplicateCount++
			continue
		}

		if repaired {
			repairedCount++
		}
		byIP[a.IP] = a
		loaded = append(loaded, a)
	}

	h.auditLock.Lock()
	h.granted = append(h.granted, loaded...)
	h.auditLock.Unlock()

	for _, a := range loaded {
		go handleBucket(a)
		log.Printf("Restored IP %s from persist file (authed %v)", a.IP, a.AuthedTime)
	}

	log.Printf("Loaded %d IP(s) from persist file", len(loaded))

	if expiredCount > 0 || duplicateCount > 0 || repairedCount > 0 || invalidCount > 0 {
		log.Printf("Cleaned persist data: removed %d expired, merged %d duplicate, repaired %d missing session, skipped %d invalid record(s)", expiredCount, duplicateCount, repairedCount, invalidCount)
		h.saveGranted()
	}
}

func authedFromPersisted(p persistedAuthed) (*authed, bool, error) {
	if strings.TrimSpace(p.IP) == "" {
		return nil, false, errMissingIP
	}

	repaired := false
	session := p.Session
	if session == "" {
		var err error
		session, err = generateSession()
		if err != nil {
			return nil, false, err
		}
		repaired = true
	}

	requests := make(map[time.Time]int, len(p.Requests))
	for bucket, count := range p.Requests {
		requests[bucket] = count
	}

	return &authed{
		IP:              p.IP,
		AuthedTime:      p.AuthedTime,
		Session:         session,
		Authed:          p.AuthedTime.Format(time.UnixDate),
		LastAccess:      p.LastAccess,
		DomainsAccessed: append([]string(nil), p.DomainsAccessed...),
		Requests:        requests,
	}, repaired, nil
}

// saveGranted writes current granted IPs to file
func (h *Handlers) saveGranted() {
	h.auditLock.Lock()
	persisted := make([]persistedAuthed, 0, len(h.granted))
	for _, a := range h.granted {
		persisted = append(persisted, snapshotPersisted(a))
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

		h.auditLock.Lock()
		removed, merged := h.compactGrantedLocked(now)
		h.auditLock.Unlock()

		if removed > 0 || merged > 0 {
			log.Printf("Cleanup: removed %d expired and merged %d duplicate IP record(s)", removed, merged)
			h.saveGranted()
		}
	}
}

// isExpired checks if an IP has expired
func (h *Handlers) isExpired(a *authed) bool {
	a.recordEditLock.Lock()
	authedTime := a.AuthedTime
	a.recordEditLock.Unlock()

	return time.Since(authedTime) > h.expirationDuration()
}

func (h *Handlers) cookieMaxAgeSeconds() int {
	return h.expirationDays * 24 * 60 * 60
}

func (h *Handlers) expirationDuration() time.Duration {
	return time.Duration(h.expirationDays) * 24 * time.Hour
}

func generateSession() (string, error) {
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(sessionBytes), nil
}

func (h *Handlers) findGrantedBySession(session string) *authed {
	if session == "" {
		return nil
	}

	h.auditLock.Lock()
	copiedGranted := make([]*authed, len(h.granted))
	copy(copiedGranted, h.granted)
	h.auditLock.Unlock()

	for _, authRecord := range copiedGranted {
		authRecord.recordEditLock.Lock()
		matches := subtle.ConstantTimeCompare([]byte(authRecord.Session), []byte(session)) == 1
		authRecord.recordEditLock.Unlock()
		if matches {
			return authRecord
		}
	}

	return nil
}

func (h *Handlers) reuseGrantedIPLocked(ip string, now time.Time) *authed {
	removed, merged := h.compactGrantedLocked(now)
	if removed > 0 || merged > 0 {
		log.Printf("Cleaned auth list: removed %d expired and merged %d duplicate IP record(s)", removed, merged)
	}

	for _, record := range h.granted {
		if record.IP == ip {
			refreshAuthRecord(record, now)
			return record
		}
	}

	return nil
}

func (h *Handlers) compactGrantedLocked(now time.Time) (int, int) {
	keptByIP := make(map[string]*authed, len(h.granted))
	compacted := h.granted[:0]
	removed := 0
	merged := 0

	for _, record := range h.granted {
		if h.recordExpiredAt(record, now) {
			record.recordEditLock.Lock()
			log.Printf("Removing expired IP %s (authed %v)", record.IP, record.AuthedTime)
			record.recordEditLock.Unlock()
			removed++
			continue
		}

		if existing := keptByIP[record.IP]; existing != nil {
			mergeAuthRecords(existing, record)
			merged++
			continue
		}

		keptByIP[record.IP] = record
		compacted = append(compacted, record)
	}

	h.granted = compacted
	return removed, merged
}

func (h *Handlers) recordExpiredAt(record *authed, now time.Time) bool {
	record.recordEditLock.Lock()
	authedTime := record.AuthedTime
	record.recordEditLock.Unlock()

	return now.Sub(authedTime) > h.expirationDuration()
}

func refreshAuthRecord(record *authed, authedAt time.Time) {
	record.recordEditLock.Lock()
	defer record.recordEditLock.Unlock()

	record.AuthedTime = authedAt
	record.Authed = authedAt.Format(time.UnixDate)
	if record.Requests == nil {
		record.Requests = make(map[time.Time]int)
	}
}

func mergeAuthRecords(keep, drop *authed) {
	if keep == nil || drop == nil || keep == drop {
		return
	}

	dropSnapshot := snapshotPersisted(drop)

	keep.recordEditLock.Lock()
	defer keep.recordEditLock.Unlock()

	if dropSnapshot.AuthedTime.After(keep.AuthedTime) {
		keep.AuthedTime = dropSnapshot.AuthedTime
		keep.Authed = dropSnapshot.AuthedTime.Format(time.UnixDate)
	}
	if keep.LastAccess == "" {
		keep.LastAccess = dropSnapshot.LastAccess
	}
	if keep.Requests == nil {
		keep.Requests = make(map[time.Time]int)
	}

	existingDomains := make(map[string]struct{}, len(keep.DomainsAccessed)+len(dropSnapshot.DomainsAccessed))
	for _, domain := range keep.DomainsAccessed {
		existingDomains[domain] = struct{}{}
	}
	for _, domain := range dropSnapshot.DomainsAccessed {
		if _, ok := existingDomains[domain]; ok {
			continue
		}
		keep.DomainsAccessed = append(keep.DomainsAccessed, domain)
		existingDomains[domain] = struct{}{}
	}

	for bucket, count := range dropSnapshot.Requests {
		keep.Requests[bucket] += count
	}
}

func snapshotPersisted(record *authed) persistedAuthed {
	record.recordEditLock.Lock()
	defer record.recordEditLock.Unlock()

	requests := make(map[time.Time]int, len(record.Requests))
	for bucket, count := range record.Requests {
		requests[bucket] = count
	}

	return persistedAuthed{
		IP:              record.IP,
		AuthedTime:      record.AuthedTime,
		Session:         record.Session,
		LastAccess:      record.LastAccess,
		DomainsAccessed: append([]string(nil), record.DomainsAccessed...),
		Requests:        requests,
	}
}
