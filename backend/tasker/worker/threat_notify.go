package worker

import (
	"ada/backend/cache"
	"ada/backend/common"
	"ada/backend/model"
	"ada/infra/base"
	"ada/infra/email"
	"ada/infra/mongo"
	netutil "ada/infra/net"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/syslog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-lark/lark"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const emailTmpl = `<!DOCTYPE html>
<html lang="{{.lang}}">
<head>
    <meta charset="UTF-8">
    <title>{{.head}} {{.titleSuffix}}</title>
    <style>
        body {
            font-family: "Microsoft YaHei UI", "PingFang SC", "Helvetica Neue", Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1890ff 0%, #096dd9 100%);
            color: #ffffff;
            padding: 20px 24px;
        }
        .header h2 {
            margin: 0;
            font-size: 18px;
            font-weight: 500;
        }
        .header .platform {
            font-size: 12px;
            opacity: 0.85;
            margin-bottom: 8px;
        }
        .content {
            padding: 24px;
        }
        .section-title {
            font-size: 14px;
            color: #333;
            font-weight: 500;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #e8e8e8;
        }
        .details-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .details-list li {
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
            font-size: 14px;
            color: #666;
        }
        .details-list li:last-child {
            border-bottom: none;
        }
        .details-list li strong {
            color: #333;
            min-width: 80px;
            display: inline-block;
        }
        .footer {
            background-color: #fafafa;
            padding: 16px 24px;
            font-size: 12px;
            color: #999;
            text-align: center;
            border-top: 1px solid #e8e8e8;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="platform">ADAegis - {{.platformName}}</div>
        <h2>{{.head}} {{.titleSuffix}}</h2>
    </div>
    <div class="content">
        <div class="section-title">{{.head}} {{.detailsLabel}}</div>
        <ul class="details-list">
            {{.details}}
        </ul>
    </div>
    <div class="footer">
        {{.footer}}
    </div>
</div>
</body>
</html>`

type notifyInfo struct {
	Title     string            `json:"title"`
	MsgType   string            `json:"msg_type"`   // alert|baseline|leak|system
	EventType string            `json:"event_type"` // sub_type 对于alert: tag[0] attack_type; 对于baseline/leak: plugin.type; 对于system: cpu/mem/disk/sensor/domain/es/ada
	Desc      string            `json:"desc"`
	Params    map[string]string `json:"params"`
	Timestamp int64             `json:"timestamp"`
}

// ThreatNotifyTask 威胁检测风险/扫描风险 通知
func (w *Worker) ThreatNotifyTask() error {
	ctx := context.Background()
	msg, err := w.env.RedisCli.BRPop(ctx, 10*time.Second, cache.AlertNotifyQueueKey).Result()
	if err != nil {
		if err == redis.Nil {
			//logger.Debug("empty redis queue to brpop, return")
			return nil
		}
		logger.Errorf("redis brpop failure:%v", err)
		return err
	}

	// msg format: []string{"rdx_key_name", "json_message"}
	if len(msg) != 2 {
		logger.Warnf("ignore invalid length msg:%v", msg)
		return nil
	}

	var notifyMsg notifyInfo
	err = json.Unmarshal([]byte(msg[1]), &notifyMsg)
	if err != nil {
		logger.Errorf("json unmarshal notify msg err:%v", msg)
		return err
	}

	lang := w.GetLanguage()
	notifyModule := getNotifyMsgTypeDesc(notifyMsg.MsgType, lang)
	title := fmt.Sprintf("%s:%s", notifyModule, notifyMsg.Title)

	var n model.Notify
	n.ID = primitive.NewObjectID()
	n.Title = title
	n.Status = 0
	n.Desc = notifyMsg.Desc
	n.MsgType = notifyMsg.MsgType
	n.EventType = notifyMsg.EventType
	n.Params = notifyMsg.Params
	n.CreateTm = time.Unix(notifyMsg.Timestamp, 0)
	err = w.env.MongoCli.Insert(n.CollectName(), &n)
	if err != nil {
		logger.Errorf("insert notify err:%v", err)
		return err
	}

	confList, err := getNotifyConfs(w.env.MongoCli, notifyModule)
	if err != nil {
		logger.Errorf("get notify conf(%s) err:%v", notifyModule, err)
		return err
	}

	// Get proxy settings from system info
	var sysInfo model.SystemInfo
	notifyProxy := false
	httpProxy := ""
	_, exist := w.env.MongoCli.FindOne(sysInfo.CollectName(), bson.M{}, &sysInfo)
	if exist && sysInfo.SystemProxy != nil {
		notifyProxy = sysInfo.SystemProxy["notify_proxy"] == "true"
		httpProxy = sysInfo.SystemProxy["http_proxy"]
	}

	for _, conf := range confList {
		if conf.Enable == "disable" {
			continue
		}
		if conf.Endpoint == "" {
			logger.Warnf("ingore notify type(%s) becasue endpoint is empty!", conf.NotifyType)
			continue
		}

		// check level
		level, _ := strconv.Atoi(n.Params["level"])
		if !base.InArray(int32(level), conf.NotifyLevel) {
			logger.Debugf("ignore alert notify push by level(%s)", n.Params["level"])
			continue
		}

		// check notify_rules
		if len(conf.NotifyRules) == 0 {
			logger.Debug("ignore alert notify push by empty rules!")
			continue
		}
		if !base.InArray(conf.NotifyRules, n.Params["rule_id"]) {
			logger.Debugf("ignore alert notify push by rules(%s)", n.Params["rule_id"])
			continue
		}

		switch conf.NotifyType {
		case "email":
			err = sendEmailNotify(notifyMsg, conf, lang)
		case "syslog":
			err = sendSyslogNotify(msg[1], conf)
		case "webhook":
			err = sendWebhookNotify(msg[1], conf, notifyProxy, httpProxy)
		default:
			logger.Errorf("invalid notify_type(%s), will igore this nofity", conf.NotifyType)
			return fmt.Errorf("invalid notify_type(%s), will igore this nofity", conf.NotifyType)
		}
	}

	return err
}

func sendEmailNotify(n notifyInfo, conf model.NotifyConf, lang string) error {
	host, ok := conf.MetaData["server"]
	if !ok {
		logger.Error("parse email.server in metadata failed")
		return fmt.Errorf("parse email.server in metadata failed")
	}
	port, ok := conf.MetaData["port"]
	if !ok {
		logger.Error("parse email.port in metadata failed")
		return fmt.Errorf("parse email.port in metadata failed")
	}
	address := net.JoinHostPort(host, port)
	_, err := net.DialTimeout("tcp", address, time.Second*20)
	if err != nil {
		logger.Errorf("network connect %s err:%v", address, err)
		return err
	}

	t, err := template.New("email").Parse(emailTmpl)
	if err != nil {
		logger.Errorf("parse email tmpl err:%v", err)
		return err
	}

	level, _ := strconv.Atoi(n.Params["level"])

	var details string
	switch n.MsgType {
	case common.NotifyMsgAlert:
		startTs, _ := strconv.ParseInt(n.Params["start_tm"], 10, 64)
		endTs, _ := strconv.ParseInt(n.Params["end_tm"], 10, 64)
		var eventType, dcHostname string
		if v, ok := common.RuleTagMap[n.EventType]; ok {
			eventType = v
		}
		if v, ok := n.Params["dc_hostname"]; ok {
			dcHostname = v
			delete(n.Params, "dc_hostname")
			delete(n.Params, "eid")
			delete(n.Params, "rule_id")
		}

		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_threat_name", lang), n.Title)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_threat_level", lang), common.RiskLevelMap[level])
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_threat_type", lang), eventType)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_affected_dc", lang), dcHostname)
		details += fmt.Sprintf("<li><strong>%s:</strong> %v</li>\n", getI18n("email_threat_details", lang), n.Params)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_start_time", lang), time.Unix(startTs, 0).Format(time.RFC3339))
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_end_time", lang), time.Unix(endTs, 0).Format(time.RFC3339))
	case common.NotifyMsgBaseline:
		var subType string
		if v, ok := n.Params["sub_type"]; ok {
			subType = v
			delete(n.Params, "sub_type")
		}

		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_baseline_name", lang), n.Title)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_baseline_type", lang), n.EventType)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_baseline_subtype", lang), subType)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_risk_level", lang), common.RiskLevelMap[level])
		details += fmt.Sprintf("<li><strong>%s:</strong> %v</li>\n", getI18n("email_risk_details", lang), n.Params)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>", getI18n("email_detect_time", lang), time.Unix(n.Timestamp, 0).Format(time.RFC3339))
	case common.NotifyMsgLeak:
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_vuln_name", lang), n.Title)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_vuln_type", lang), n.EventType)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_risk_level", lang), common.RiskLevelMap[level])
		details += fmt.Sprintf("<li><strong>%s:</strong> %v</li>\n", getI18n("email_vuln_details", lang), n.Params)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>", getI18n("email_detect_time", lang), time.Unix(n.Timestamp, 0).Format(time.RFC3339))
	case common.NotifyMsgSystem:
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_msg_type", lang), n.Title)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_component_type", lang), n.EventType)
		details += fmt.Sprintf("<li><strong>%s:</strong> %v</li>\n", getI18n("email_alert_details", lang), n.Params)
		details += fmt.Sprintf("<li><strong>%s:</strong> %s</li>\n", getI18n("email_start_time", lang), time.Unix(n.Timestamp, 0).Format(time.RFC3339))
	}

	buf := new(bytes.Buffer)
	head := getNotifyMsgTypeDesc(n.MsgType, lang)
	langCode := "zh"
	if lang == common.LangEn {
		langCode = "en"
	}
	err = t.Execute(buf, map[string]any{
		"lang":         langCode,
		"head":         head,
		"titleSuffix":  getI18n("email_title_suffix", lang),
		"platformName": getI18n("email_platform_name", lang),
		"detailsLabel": getI18n("email_details_label", lang),
		"details":      template.HTML(details),
		"footer":       getI18n("email_footer", lang),
	})
	if err != nil {
		logger.Errorf("execute email tmpl err:%v", err)
		return err
	}

	err = email.SendEmailV2(conf.MetaData, "ADAegis-System", buf.String())
	if err != nil {
		logger.Infof("send alarm email failed: %v", err)
		if err.Error() == "550 too many message send today." {
			logger.Errorf("send too many alarm emails today,err: %v", err)
		}
		return err
	}

	return nil
}

func sendSyslogNotify(msg string, conf model.NotifyConf) error {
	u, err := url.Parse(conf.Endpoint) // endpoint: udp://192.168.1.2:514
	if err != nil {
		logger.Errorf("parse endpoint(%s) err:%v", conf.Endpoint, err)
		return err
	}

	w, err := syslog.Dial(u.Scheme, u.Host, syslog.LOG_ALERT, "ADAegis-System")
	if err != nil {
		logger.Errorf("dial syslog err:%v", err)
		return err
	}
	defer w.Close()

	return w.Alert(msg)
}

func sendWebhookNotify(msg string, conf model.NotifyConf, notifyProxy bool, httpProxy string) error {
	appType, ok := conf.MetaData["application_type"]
	if ok {
		if appType == "feishu" {
			return sendWebhookFeishuNotify(msg, conf)
		} else if appType == "weixin" || appType == "dingtalk" {
			return sendWebhookWeixinOrDingtalkNotify(msg, conf, notifyProxy, httpProxy)
		}
	}

	// Create HTTP client with proxy support
	var client *http.Client
	if notifyProxy && httpProxy != "" {
		client = netutil.NewHTTPClientWithProxy(httpProxy, 10)
	} else {
		client = netutil.NewHTTPClient(10)
	}

	data := fmt.Appendf(nil, `"title":"ADA-System","message":"%s"}`, msg)
	req, err := http.NewRequest("POST", conf.Endpoint, bytes.NewReader(data))
	if err != nil {
		logger.Errorf("webhook http request(%s) err:%v", conf.Endpoint, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("do request(%s) err:%v", conf.Endpoint, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Errorf("send webhook request(%s) done, but response code:%d", conf.Endpoint, resp.StatusCode)
		return err
	}

	return nil
}

func sendWebhookFeishuNotify(msg string, conf model.NotifyConf) error {
	bot := lark.NewNotificationBot(conf.Endpoint)
	mbPost := lark.NewMsgBuffer(lark.MsgPost)
	mbPost.Post(lark.NewPostBuilder().Title("ADA-System").TextTag(msg, 1, true).Render())
	ret, err := bot.PostNotificationV2(mbPost.Build())
	if err != nil {
		logger.Errorf("send notify webhook(feishu) err:%v, status_msg:%s", err, ret.StatusMessage)
		return err
	}

	logger.Debugf("send notify webhook(feishu) ok, msg:%s", msg)

	return nil
}

func sendWebhookWeixinOrDingtalkNotify(msg string, conf model.NotifyConf, notifyProxy bool, httpProxy string) error {
	// Create HTTP client with proxy support
	var client *http.Client
	if notifyProxy && httpProxy != "" {
		client = netutil.NewHTTPClientWithProxy(httpProxy, 10)
	} else {
		client = netutil.NewHTTPClient(10)
	}

	data := fmt.Appendf(nil, `{"msgtype":"text","text":{"content": "%s"}}`, msg)
	req, err := http.NewRequest("POST", conf.Endpoint, bytes.NewReader(data))
	if err != nil {
		logger.Errorf("webhook http request(%s) err:%v", conf.Endpoint, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("do request(%s) err:%v", conf.Endpoint, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Errorf("send webhook request(%s) done, but response code:%d", conf.Endpoint, resp.StatusCode)
		return err
	}

	logger.Debugf("send notify webhook(winxin/dingtalk) ok, msg:%s", msg)

	return nil
}

func getNotifyConfs(m mongo.DBAdaptor, moduleName string) ([]model.NotifyConf, error) {
	var nc []model.NotifyConf
	tb := (&model.NotifyConf{}).CollectName()

	if err := m.FindAll(tb, bson.M{"module_name": moduleName}, &nc); err != nil {
		return nil, err
	}

	return nc, nil
}
