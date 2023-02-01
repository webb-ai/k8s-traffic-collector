package vm

import (
	"github.com/gorilla/websocket"
)

type Log struct {
	Script    int64  `json:"script"`
	Color     string `json:"color"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

var LogSockets []*websocket.Conn

func RecieveLogChannel(logChannel chan *Log) {
	for log := range logChannel {
		for _, ws := range LogSockets {
			ws.WriteJSON(log)
		}
	}
}
