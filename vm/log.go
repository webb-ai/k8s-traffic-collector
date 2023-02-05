package vm

import (
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type Log struct {
	Script    int64     `json:"script"`
	Suffix    string    `json:"suffix"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

type LogState struct {
	Sockets []*websocket.Conn
	Channel chan *Log
	sync.Mutex
}

var LogGlobal *LogState

func RecieveLogChannel() {
	for l := range LogGlobal.Channel {
		LogGlobal.Lock()
		sockets := LogGlobal.Sockets
		LogGlobal.Unlock()
		for _, ws := range sockets {
			err := ws.WriteMessage(1, []byte(fmt.Sprintf("%d%s] %s", l.Script, l.Suffix, l.Text)))
			if err != nil {
				log.Error().Err(err).Send()
			}
		}
	}
}

func SendLog(scriptIndex int64, msg string) {
	LogGlobal.Channel <- &Log{
		Script:    scriptIndex,
		Suffix:    "",
		Text:      msg,
		Timestamp: time.Now(),
	}
}

func SendLogError(scriptIndex int64, msg string) {
	LogGlobal.Channel <- &Log{
		Script:    scriptIndex,
		Suffix:    ":ERROR",
		Text:      msg,
		Timestamp: time.Now(),
	}
}
