package email

import (
	"crypto/tls"
	"fmt"
	"net"
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

// 邮件发送
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

func SendEmail(cnf map[string]string, subject, body string) error {
	username, ok := cnf["sender_username"]
	if !ok {
		return fmt.Errorf("empty param of sender_username")
	}
	password, ok := cnf["sender_identity"]
	if !ok {
		return fmt.Errorf("empty param of sender_identity")
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
	auth := smtp.PlainAuth("", username, password, host)

	subject = strings.ReplaceAll(subject, "\n", "")

	msg := fmt.Sprintf("To: %s\r\nFrom: %s", to, nickname)
	msg += fmt.Sprintf("<%s>\r\nSubject: %s\r\n%s\r\n\r\n", username, subject, contentType)
	msg += fmt.Sprintf("<html><body>%s</body></html>", body)
	smtpSrv := fmt.Sprintf("%s:%s", host, port)

	err := smtp.SendMail(smtpSrv, auth, username, strings.Split(to, ","), []byte(msg))
	if err != nil {
		logger.Printf("send mail error: %v", err)
		return err
	}
	return nil
}

func smtpSendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		host, _, _ := net.SplitHostPort(addr)
		config := &tls.Config{InsecureSkipVerify: true, ServerName: host}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(a); err != nil {
				return err
			}
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}
