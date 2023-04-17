package web

import (
	"html/template"
	"log"
)

var (
	allowed []*authed
)

type Handlers struct {
	Templates *template.Template
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
	return Handlers{Templates: templates}
}
