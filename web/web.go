package web

import (
	"html/template"
	"log"
	"os"
)

var (
	allowed []*authed
)

type Handlers struct {
	Templates    *template.Template
	UnlockPasswd string
}

type authed struct {
	IP              string
	Authed          string
	LastAccess      string
	DomainsAccessed []string
}

func SetupHandlers() Handlers {
	templates, err := template.ParseGlob("web/src/*.html")
	if err != nil {
		log.Fatalf("%s\n", err)
		return Handlers{}
	}

	unlockPasswd := os.Getenv("GATEWAY_PASSWORD")

	return Handlers{Templates: templates, UnlockPasswd: unlockPasswd}
}
