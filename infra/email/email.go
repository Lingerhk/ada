package email

import (
	"fmt"
	"net/smtp"
	"strings"

	logger "github.com/sirupsen/logrus"
)

type emailAuth struct {
	username, password string
}

func loginAuth(username, password string) smtp.Auth {
	return &emailAuth{username, password}
}
func (a *emailAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}
func (a *emailAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		}
	}
	return nil, nil
}

// SendEmailV2 sends email
func SendEmailV2(cnf map[string]string, subject, body string) error {
	username, ok := cnf["username"]
	if !ok {
		return fmt.Errorf("empty param of username")
	}
	password, ok := cnf["password"]
	if !ok {
		return fmt.Errorf("empty param of password")
	}
	host, ok := cnf["server"]
	if !ok {
		return fmt.Errorf("empty param of server")
	}
	port, ok := cnf["port"]
	if !ok {
		return fmt.Errorf("empty param of port")
	}
	to, ok := cnf["receiver"]
	if !ok {
		return fmt.Errorf("empty param of receiver")
	}
	nickname := username

	contentType := "Content-Type: text/html; charset=UTF-8"
	auth := loginAuth(username, password)

	msg := fmt.Sprintf("To: %s\r\nFrom: %s", to, nickname)
	msg += fmt.Sprintf("<%s>\r\nSubject: %s\r\n%s\r\n\r\n", username, subject, contentType)
	msg += body
	smtpSrv := fmt.Sprintf("%s:%s", host, port)

	err := smtp.SendMail(smtpSrv, auth, username, strings.Split(to, ","), []byte(msg))
	if err != nil {
		logger.Warnf("send mail error: %v", err)
		return err
	}
	return nil
}
