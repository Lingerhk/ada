// desc: 此Service为同步事情处理（非异步调度）

package server

import (
	sCommon "ada/agent/sensor/common"
	"ada/backend/cache"
	"context"
	"github.com/redis/go-redis/v9"
	"runtime/debug"
	"sync"
	"time"

	"ada/backend/tasker/config"
	"ada/backend/tasker/event"
	logger "github.com/sirupsen/logrus"
)

type PubsubServer struct {
	ctx    context.Context
	env    *config.Env
	cancel context.CancelFunc
}

func NewPubsubServer(env *config.Env) *PubsubServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &PubsubServer{
		ctx:    ctx,
		env:    env,
		cancel: cancel,
	}
}

func (p *PubsubServer) EventsServe() {
	wg := sync.WaitGroup{}
	wg.Add(2)

	// 在此定义所有添加的Events
	go p.PubsubSensorEvent(&wg)
	go p.PubsubLdapEvent(&wg)

	wg.Wait()
}

func (p *PubsubServer) Stop() {
	p.cancel()
}

// Events: redis pub/sub事件
func (p *PubsubServer) PubsubSensorEvent(wg *sync.WaitGroup) {
	defer wg.Done()

	defer func() {
		if e := recover(); e != nil {
			logger.Errorf("PubsubSensorEvent crashed, err: %s\ntrace:%s", e, string(debug.Stack()))
		}
	}()

	// Sensor Event
	se := event.NewSensorEvent(p.env.RedisCli, p.env.MongoCli)

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			time.Sleep(1 * time.Second)
			queueLen, err := p.env.RedisCli.LLen(p.ctx, sCommon.SensorStateQueue).Result()
			if err != nil {
				logger.Errorf("redis llen %s err:%v", sCommon.SensorStateQueue, err)
				continue
			}
			if queueLen == 0 {
				continue
			}

			msg, err := p.env.RedisCli.RPop(p.ctx, sCommon.SensorStateQueue).Result()
			if err != nil {
				logger.Errorf("redis rpop err:%v", err)
				continue
			}

			logger.Debugf("received sensor event:%v", msg)

			go se.Process(msg) // 确保不会卡住队列
		}
	}
}

// Events: redis pub/sub事件, pub来自engine
func (p *PubsubServer) PubsubLdapEvent(wg *sync.WaitGroup) {
	defer wg.Done()

	defer func() {
		if e := recover(); e != nil {
			logger.Errorf("PubsubLdapEvent crashed, err: %s\ntrace:%s", e, string(debug.Stack()))
		}
	}()

	// Ldap search Event
	le := event.NewLdapEvent(p.env.RedisCli)
	pubsub := p.env.RedisCli.PSubscribe(p.ctx, cache.LdapSearchPubsubChan)
	defer pubsub.Close()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			msg, err := pubsub.ReceiveTimeout(p.ctx, 5*time.Second)
			if err != nil {
				if err := pubsub.Ping(p.ctx); err != nil {
					logger.Errorf("PubSub ping failure:%s", err.Error())
					// TODO: check this if redis is down.
					//return
				}
				continue
			}
			switch msg := msg.(type) {
			case *redis.Message:
				logger.Infof("channel: %s received:%s, ", msg.Channel, msg.Payload)
				go le.Process(msg.Channel, msg.Payload)
			}
		}
	}
}
