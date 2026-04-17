package web

import (
	"fmt"
	"log"
	"net/smtp"
	"time"
)

func (h *Handlers) sendUnlockNotification(ip string) {
	if h.smtpHost == "" || h.notifyEmail == "" {
		return
	}

	addr := fmt.Sprintf("%s:%s", h.smtpHost, h.smtpPort)
	auth := smtp.PlainAuth("", h.smtpUser, h.smtpPass, h.smtpHost)

	subject := fmt.Sprintf("Gateway: IP %s unlocked", ip)
	body := fmt.Sprintf("IP address %s was granted access at %s.", ip, time.Now().Format(time.RFC1123))
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		h.smtpUser, h.notifyEmail, subject, body,
	))

	if err := smtp.SendMail(addr, auth, h.smtpUser, []string{h.notifyEmail}, msg); err != nil {
		log.Printf("Failed to send unlock notification: %v", err)
	}
}
