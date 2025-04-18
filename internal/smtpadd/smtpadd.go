package smtpadd

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
)

func SendToEmail(mail string, ip string) {
	addr := os.Getenv("MAIL_HOST") + ":" + os.Getenv("MAIL_PORT")
	auth := smtp.PlainAuth("", os.Getenv("MAIL_USERNAME"), os.Getenv("MAIL_PASSWORD"), os.Getenv("MAIL_HOST"))
	subject := "WARN"
	body := "Login from new IP: " + ip
	message := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)
	err := smtp.SendMail(addr, auth, os.Getenv("MAIL_FROM_ADDRESS"), []string{mail}, []byte(message))
	if err != nil {
		log.Println(err)
	}
}
