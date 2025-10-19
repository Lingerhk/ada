package util

import (
	"ada/backend/apiserver/common"
	"ada/infra/base"
	"ada/infra/license"
	"ada/infra/otp"
	"context"
	"crypto/sha1"
	"encoding/base32"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	sshUser          = "adadmin"
	sshPrivKey       = "/home/adadmin/.ssh/id_rsa"
	websshLockKey    = "ada:webssh:lock"
	websshCounterKey = "ada:webssh:counter"
)

// 设备信息
type DeviceInfo struct {
	DeviceId string
	SshHost  string
	SshUser  string
	SshPwd   string
}

var deviceInfoList = make(map[string]*DeviceInfo)

type MyOutput struct {
	WsConn *websocket.Conn
}

func (out *MyOutput) Write(p []byte) (n int, err error) {
	err = out.WsConn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

type WebSshStreamer struct {
	redisCli *redis.Client
}

func NewWebSshStream(redisCli *redis.Client) *WebSshStreamer {
	return &WebSshStreamer{redisCli: redisCli}
}

// -- 登录失败计数器 --
func (wss *WebSshStreamer) LoginLocked() bool {
	ctx := context.Background()
	val, err := wss.redisCli.Get(ctx, websshLockKey).Result()
	if err == redis.Nil {
		return false
	} else if err != nil {
		logger.Errorf("redis get err:%v", err)
		return true
	}

	if base.Atoll(val) > 3 {
		err = wss.redisCli.Expire(ctx, websshLockKey, 5*time.Minute).Err()
		if err != nil {
			logger.Errorf("redis set expire err:%v", err)
		}
		return true
	}

	return false
}

func (wss *WebSshStreamer) LoginFailed() {
	ctx := context.Background()
	_ = wss.redisCli.Incr(ctx, websshLockKey).Err()
	_ = wss.redisCli.Expire(ctx, websshLockKey, 5*time.Minute).Err()
}

func (wss *WebSshStreamer) LoginOk() {
	_ = wss.redisCli.Del(context.Background(), websshLockKey).Err()
}

// WebSshStream websocket接口
func (wss *WebSshStreamer) Stream(c *gin.Context) {
	wsKey := c.GetHeader("Sec-WebSocket-Key")
	conn, err := (&websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		return true
	}, Subprotocols: []string{wsKey}}).Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.Errorf("websocket upgrader err: %v", err)
		c.JSON(http.StatusOK, gin.H{"err": "websocket init err"})
		return
	} else {
		if wss.LoginLocked() {
			_ = conn.WriteJSON("账户已锁定")
			conn.Close()
			return
		}

		//客户端连接后获取参数
		code := c.Query("code")
		token := c.Query("token")
		if len(code) != 8 || len(token) > 180 {
			wss.LoginFailed()
			_ = conn.WriteJSON("验证失败")
			conn.Close()
			return
		}

		claim, err := ParseToken(token, common.JWT_SECRET)
		if err != nil {
			logger.Errorf("parse token err:%v", err)
			wss.LoginFailed()
			_ = conn.WriteJSON("身份验证失败，请登录平台账户。")
			conn.Close()
			return
		}
		if claim.Role != "1" && claim.Expired < time.Now().Unix() {
			wss.LoginFailed()
			_ = conn.WriteJSON("请使用管理员账户")
			conn.Close()
			return
		}

		licer, err := license.NewAdaLicense(wss.redisCli)
		if err != nil {
			logger.Errorf("new license client err:%v", err)
			_ = conn.WriteJSON("内部错误")
			conn.Close()
			return
		}

		authed := wss.mfaVerify(licer.GetTrait(), code)
		if !authed {
			wss.LoginFailed()
			_ = conn.WriteJSON("验证失败")
			conn.Close()
			return
		}

		// 判断当前已打开的终端数，最多2个
		if len(deviceInfoList) > 2 {
			logger.Warnf("too many session(%d) opened, exit!", len(deviceInfoList))
			conn.Close()
			return
		}

		deviceId := claim.User
		deviceInfoList[deviceId] = &DeviceInfo{
			DeviceId: deviceId,
			SshHost:  "127.0.0.1:22",
			SshUser:  sshUser,
		}

		logger.Infof("new connect from %s, deviceId:%s, ua:%s", c.ClientIP(), deviceId, c.Request.UserAgent())
		wss.LoginOk()

		go wss.ws2ssh(conn, deviceId)
	}
}

// 根据设备id获取ssh连接配置
func getSshConfigByDeviceId(deviceId string) (string, *ssh.ClientConfig) {
	deviceInfo := deviceInfoList[deviceId]
	if deviceInfo == nil {
		return "", nil
	}

	privateKeyBytes, err := os.ReadFile(sshPrivKey)
	if err != nil {
		logger.Errorf("read ras pub failed,err:%v", err)
		return "", nil
	}

	key, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		logger.Errorf("parse private key failed,err:%v", err)
		return "", nil
	}

	sshConfig := &ssh.ClientConfig{
		User: deviceInfo.SshUser,
		Auth: []ssh.AuthMethod{
			//ssh.Password(deviceInfo.SshPwd),
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "",
		Timeout:         5 * time.Second,
	}
	return deviceInfo.SshHost, sshConfig
}

// 建立ssh连接
func (wss *WebSshStreamer) sshConnect(deviceId string) (*ssh.Session, io.WriteCloser, error) {
	addr, sshConfig := getSshConfigByDeviceId(deviceId)
	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		logger.Errorf("ssh connect %s(deviceId:%s) err:%v", addr, deviceId, err)
		return nil, nil, err
	}

	//https://tools.ietf.org/html/rfc4254#page-10
	session, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		logger.Errorf("ssh session(srv:%s) create(deviceId:%s) err:%v", addr, deviceId, err)
		return nil, nil, err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     //打开回显
		ssh.TTY_OP_ISPEED: 14400, //输入速率 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, //输出速率 14.4kbaud
		ssh.VSTATUS:       1,
	}

	//https://tools.ietf.org/html/rfc4254#page-11
	var termHeight, termWidth int = 50, 180
	err = session.RequestPty("xterm-256color", termHeight, termWidth, modes)
	//err = session.RequestPty("xterm", termHeight, termWidth, modes)
	if err != nil {
		session.Close()
		sshClient.Close()
		logger.Errorf("ssh terminal(srv:%s) create(deviceId:%s) err:%v", addr, deviceId, err)
		return nil, nil, err
	}

	pipeInput, err := session.StdinPipe()
	if err != nil {
		session.Close()
		sshClient.Close()
		logger.Errorf("ssh terminal(srv:%s) pipe create(deviceId:%s) err:%v", addr, deviceId, err)
		return nil, nil, err
	}

	//https://tools.ietf.org/html/rfc4254#page-13
	err = session.Shell()
	if err != nil {
		session.Close()
		sshClient.Close()
		logger.Errorf("ssh shell(srv:%s) open(deviceId:%s) err:%v", addr, deviceId, err)
		return nil, nil, err
	}

	go func() {
		//等待远程命令结束或远程shell退出
		err = session.Wait()
		if err != nil {
			// web端异常关闭的时候，会导致这里异常关闭，可忽略该错误(降为info)
			logger.Infof("ssh session(addr:%s, deviceId:%s) closed with err:%v", addr, deviceId, err)
		}
	}()

	return session, pipeInput, nil
}

// 打通websocket 到 ssh之间的连接
func (wss *WebSshStreamer) ws2ssh(wsConn *websocket.Conn, deviceId string) {
	session, pipeInput, err := wss.sshConnect(deviceId)
	if err != nil {
		wsConn.Close()
		return
	}

	session.Stdout = &MyOutput{WsConn: wsConn}
	go wss.streamBind(wsConn, deviceId, session, pipeInput)
}

// 流绑定
func (wss *WebSshStreamer) streamBind(wsConn *websocket.Conn, deviceId string, session *ssh.Session, pipeInput io.WriteCloser) {
	defer wsConn.Close()
	defer session.Close()
	for {
		_, msg, err := wsConn.ReadMessage()
		if err != nil {
			// web端读取异常的时候，会导致这里异常关闭，可忽略该错误(降为info)
			logger.Infof("read websocket pipe failed, will closed stearm(deviceId:%s). err:%v", deviceId, err)
			break
		}

		n, err := pipeInput.Write(msg)
		if err != nil {
			logger.Errorf("forward(deviceId:%s) msg to ssh shell failed, will closed stream. err:%v", deviceId, len(msg))
			break
		}

		logger.Debugf("forward(deviceId:%s) websocket pipe msg to ssh with len:%d", deviceId, n)
	}

	logger.Infof("connect(deviceId:%s) closed, will close ssh session.", deviceId)
}

func (wss *WebSshStreamer) mfaVerify(trait, inputCode string) bool {
	secret := base32.StdEncoding.EncodeToString([]byte(trait))

	var codeLength = 8 // 默认mfa code长度
	hasher := &otp.Hasher{
		HashName: "sha1",
		Digest:   sha1.New,
	}

	ctx := context.Background()
	counter, err := wss.redisCli.Get(ctx, websshCounterKey).Int()
	if err != nil && err == redis.Nil {
		counter = 4202
		_ = wss.redisCli.IncrBy(ctx, websshCounterKey, int64(counter)).Err()
	}

	hotp := otp.NewHOTP(secret[:32], codeLength, hasher)
	for code := counter; code < counter+2000; code++ {
		retVal := hotp.Verify(inputCode, code)
		if retVal {
			_ = wss.redisCli.Incr(ctx, websshCounterKey).Err()
			return true
		}
	}

	return false
}
