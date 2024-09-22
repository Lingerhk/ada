package event

import (
	"ada/infra/mongo"
	"github.com/redis/go-redis/v9"
)

type LdapEvent struct {
	redisCli *redis.Client
	mongoCli mongo.DBAdaptor
}

func NewLdapEvent(redisCli *redis.Client) *LdapEvent {
	return &LdapEvent{redisCli: redisCli}
}

func (l *LdapEvent) Process(msgChan, msgData string) {

	return
}
