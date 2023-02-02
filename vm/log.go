package vm

import (
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

type Log struct {
	Script    int64     `json:"script"`
	Suffix    string    `json:"suffix"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

var LogSockets []*websocket.Conn

func RecieveLogChannel(logChannel chan *Log) {
	for log := range logChannel {
		for _, ws := range LogSockets {
			ws.WriteMessage(1, []byte(fmt.Sprintf("%d%s] %s", log.Script, log.Suffix, log.Text)))
		}
	}
}
