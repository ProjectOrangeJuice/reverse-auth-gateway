package web

import (
	"html/template"
	"log"
	"os"
	"sync"
	"time"
)

type Handlers struct {
	Templates    *template.Template
	unlockPasswd string

	auditLock sync.Mutex // Not concerned for performance
	granted   []*authed
	activity  sync.Map
}

type authed struct {
	IP              string
	Authed          string
	LastAccess      string
	DomainsAccessed []string

	Requests map[time.Time]int

	recordEditLock sync.Mutex
}

func SetupHandlers() Handlers {
	templates, err := template.ParseGlob("web/src/*.html")
	if err != nil {
		log.Fatalf("%s\n", err)
		return Handlers{}
	}

	unlockPasswd := os.Getenv("GATEWAY_PASSWORD")

	return Handlers{Templates: templates, unlockPasswd: unlockPasswd}
}
