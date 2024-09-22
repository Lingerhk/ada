package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/go-lark/lark"
	"github.com/gregdel/pushover"
	"github.com/redis/go-redis/v9"
	"strings"
	"time"
)

const redisURI = "redis://:1pa2YgE3jfTbVVpn06CN@192.168.18.4:6379/0"

var notifyMap map[string]int64

// 监听redis log hook queue, 并推送error level告警
func main() {
	ctx := context.Background()
	notifyMap = make(map[string]int64)

	opt, err := redis.ParseURL(redisURI)
	if err != nil {
		panic(err)
	}

	opt.DialTimeout = 15 * time.Second
	opt.ReadTimeout = 15 * time.Second
	opt.WriteTimeout = 15 * time.Second
	opt.PoolSize = 100

	rdb := redis.NewClient(opt)
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}

	// queue name
	queues := []string{"ada:logs_queue:apiserver", "ada:logs_queue:sensor", "ada:logs_queue:task_worker", "ada:logs_queue:task_worker", "ada:logs_queue:receiver", "ada:logs_queue:engine", "ada:logs_queue:scanner"}

	for {
		time.Sleep(2 * time.Second)

		msg, err := rdb.BRPop(ctx, 10*time.Second, queues...).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			fmt.Printf("redis brpop failure:%v", err)
			panic(err)
		}

		if len(msg) != 2 {
			fmt.Println("invalid length msg, ignore!")
			continue
		}

		hasher := md5.New()
		_, err = hasher.Write([]byte(msg[1]))
		if err != nil {
			fmt.Printf("hasher msg err:%v\n", err)
			continue
		}

		nowTs := time.Now().Unix()
		hashStr := hex.EncodeToString(hasher.Sum(nil))
		if ts, ok := notifyMap[hashStr]; ok && nowTs-ts < 60 {
			fmt.Println("ignore the same msg within 10s!")
			continue
		}

		//pushAlert(msg[0], msg[1])
		pushFeishu(msg[0], msg[1])
		notifyMap[hashStr] = nowTs

		for k, ts := range notifyMap {
			if nowTs-ts > 3600 {
				delete(notifyMap, k)
			}
		}
	}
}

func pushAlert(module, cnt string) {
	parts := strings.SplitN(module, "logs_queue:", 2)

	const COM_UKEY = "unowa27ankv98ty8gbbprsef5ak7ub"
	app := pushover.New("arf6n44wtk5sgrw8jbqn2thjgp141p")
	recipient := pushover.NewRecipient(COM_UKEY)

	message := &pushover.Message{
		Message:   cnt,
		Title:     fmt.Sprintf("ADA-%s", parts[1]),
		Priority:  pushover.PriorityNormal,
		Timestamp: time.Now().Unix(),
		Sound:     pushover.SoundBike,
	}

	_, err := app.SendMessage(message, recipient)
	if err != nil {
		fmt.Printf("send pushover err:%v\n", err)
		return
	}

	fmt.Printf("send alert(%s) to pushover ok\n", parts[1])
}

func pushFeishu(module, cnt string) {
	bot := lark.NewNotificationBot("https://open.feishu.cn/open-apis/bot/v2/hook/6cd351a0-343b-4c9f-bee7-63324d9d392a")

	parts := strings.SplitN(module, "logs_queue:", 2)
	title := fmt.Sprintf("ADA-%s", parts[1])

	mbPost := lark.NewMsgBuffer(lark.MsgPost)
	mbPost.Post(lark.NewPostBuilder().Title(title).TextTag(cnt, 1, true).Render())
	_, err := bot.PostNotificationV2(mbPost.Build())
	if err != nil {
		fmt.Printf("send feishu err:%v\n", err)
		return
	}

	fmt.Printf("send alert(%s) to feishu ok\n", parts[1])
}
