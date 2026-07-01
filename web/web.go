package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Handlers struct {
	Templates    *template.Template
	unlockPasswd string

	grantedLock    sync.Mutex // Not concerned for performance
	granted        map[string]*authed
	saveLock       sync.Mutex // serializes persist-file writes (atomic save)
	persistFile    string
	expirationDays int
	cookieDomain   string
	cookieName     string
	clientIPHeader string

	loginLock        sync.Mutex
	loginAttempts    map[string]*loginAttempt
	maxLoginFailures int
	lockoutDuration  time.Duration

	slackWebhook string // optional Incoming Webhook URL (from SLACK_WEBHOOK_URL; "" = silent no-op)
}

type authed struct {
	IP         string    `json:"ip"`
	AuthedTime time.Time `json:"authed_time"`
	Session    string    `json:"session"`

	recordEditLock sync.Mutex `json:"-"`
}

type persistedAuthed struct {
	IP         string    `json:"ip"`
	AuthedTime time.Time `json:"authed_time"`
	Session    string    `json:"session"`
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
	clientIPHeader := os.Getenv("CLIENT_IP_HEADER")
	if clientIPHeader == "" {
		clientIPHeader = "X-Gateway-Client-IP"
	}

	expirationDays := 30 // default
	if expStr := os.Getenv("IP_EXPIRATION_DAYS"); expStr != "" {
		if days, err := strconv.Atoi(expStr); err == nil && days > 0 {
			expirationDays = days
		} else {
			log.Printf("Invalid IP_EXPIRATION_DAYS value '%s', using default of 30 days", expStr)
		}
	}

	maxLoginFailures := 5 // lock the IP out after this many failed unlocks
	if v := os.Getenv("MAX_LOGIN_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxLoginFailures = n
		} else {
			log.Printf("Invalid MAX_LOGIN_FAILURES value '%s', using default of 5", v)
		}
	}

	lockoutMinutes := 15 // how long a locked-out IP stays locked
	if v := os.Getenv("LOCKOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lockoutMinutes = n
		} else {
			log.Printf("Invalid LOCKOUT_MINUTES value '%s', using default of 15", v)
		}
	}

	slackWebhook := os.Getenv("SLACK_WEBHOOK_URL")

	h := Handlers{
		Templates:        templates,
		unlockPasswd:     unlockPasswd,
		persistFile:      persistFile,
		expirationDays:   expirationDays,
		cookieDomain:     cookieDomain,
		cookieName:       cookieName,
		clientIPHeader:   clientIPHeader,
		granted:          make(map[string]*authed),
		loginAttempts:    make(map[string]*loginAttempt),
		maxLoginFailures: maxLoginFailures,
		lockoutDuration:  time.Duration(lockoutMinutes) * time.Minute,
		slackWebhook:     slackWebhook,
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

func newAuthed(ip string, authedAt time.Time) (*authed, error) {
	session, err := generateSession()
	if err != nil {
		return nil, err
	}

	return &authed{
		IP:         ip,
		AuthedTime: authedAt,
		Session:    session,
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
	loaded := make([]*authed, 0, len(persisted))
	expiredCount := 0
	duplicateCount := 0
	repairedCount := 0
	invalidCount := 0

	h.grantedLock.Lock()
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

		if existing := h.granted[a.IP]; existing != nil {
			mergeAuthRecords(existing, a)
			duplicateCount++
			continue
		}

		if repaired {
			repairedCount++
		}
		h.granted[a.IP] = a
		loaded = append(loaded, a)
	}
	h.grantedLock.Unlock()

	for _, a := range loaded {
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

	return &authed{
		IP:         p.IP,
		AuthedTime: p.AuthedTime,
		Session:    session,
	}, repaired, nil
}

// saveGranted writes current granted IPs to file. Writes are serialized behind
// saveLock and committed atomically (temp file + rename) so concurrent grants
// can't interleave and a crash mid-write can't truncate the file -- a truncated
// file fails to parse on startup and drops every authorized IP.
func (h *Handlers) saveGranted() {
	h.saveLock.Lock()
	defer h.saveLock.Unlock()

	h.grantedLock.Lock()
	persisted := make([]persistedAuthed, 0, len(h.granted))
	for _, a := range h.granted {
		persisted = append(persisted, snapshotPersisted(a))
	}
	h.grantedLock.Unlock()

	data, err := json.Marshal(persisted)
	if err != nil {
		log.Printf("Error marshaling granted IPs: %v", err)
		return
	}

	tmp := h.persistFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("Error writing persist file: %v", err)
		return
	}

	if err := os.Rename(tmp, h.persistFile); err != nil {
		log.Printf("Error replacing persist file: %v", err)
		_ = os.Remove(tmp)
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

		h.grantedLock.Lock()
		removed, merged := h.compactGrantedLocked(now)
		h.grantedLock.Unlock()

		h.pruneLoginAttempts(now)

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

	h.grantedLock.Lock()
	// Snapshot the values under lock (map iteration is safe to snapshot pointers)
	copied := make([]*authed, 0, len(h.granted))
	for _, a := range h.granted {
		copied = append(copied, a)
	}
	h.grantedLock.Unlock()

	for _, authRecord := range copied {
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

	if record := h.granted[ip]; record != nil {
		refreshAuthRecord(record, now)
		return record
	}

	return nil
}

func (h *Handlers) compactGrantedLocked(now time.Time) (int, int) {
	removed := 0
	merged := 0

	for ip, record := range h.granted {
		if h.recordExpiredAt(record, now) {
			record.recordEditLock.Lock()
			log.Printf("Removing expired IP %s (authed %v)", record.IP, record.AuthedTime)
			record.recordEditLock.Unlock()
			delete(h.granted, ip)
			removed++
			continue
		}
		// No duplicate merging needed in map representation (keys unique by design)
	}

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
	}
}

func snapshotPersisted(record *authed) persistedAuthed {
	record.recordEditLock.Lock()
	defer record.recordEditLock.Unlock()

	return persistedAuthed{
		IP:         record.IP,
		AuthedTime: record.AuthedTime,
		Session:    record.Session,
	}
}

// notify sends a Slack notification (if configured) for successful unlock or incorrect password attempt.
func (h *Handlers) notify(ip string, unlocked bool) {
	if h.slackWebhook == "" {
		return
	}

	text := ip + " incorrect password"
	if unlocked {
		text = ip + " unlocked"
	}

	payload := map[string]string{"text": text}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal Slack payload: %v", err)
		return
	}

	// Per-call *http.Client (with timeout) inside goroutine for minimal diff and
	// to avoid introducing shared mutable state in Handlers.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(h.slackWebhook, "application/json", bytes.NewReader(data))
	if resp != nil {
		resp.Body.Close()
	}
	if err != nil {
		log.Printf("Failed to send Slack notification: %v", err)
		return
	}
}
