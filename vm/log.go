package vm

import (
	"fmt"
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

var LogSockets []*websocket.Conn
var LogChannel chan *Log

func RecieveLogChannel() {
	for l := range LogChannel {
		for _, ws := range LogSockets {
			err := ws.WriteMessage(1, []byte(fmt.Sprintf("%d%s] %s", l.Script, l.Suffix, l.Text)))
			if err != nil {
				log.Error().Err(err).Send()
			}
		}
	}
}

func SendLog(scriptIndex int64, msg string) {
	LogChannel <- &Log{
		Script:    scriptIndex,
		Suffix:    "",
		Text:      msg,
		Timestamp: time.Now(),
	}
}

func SendLogError(scriptIndex int64, msg string) {
	LogChannel <- &Log{
		Script:    scriptIndex,
		Suffix:    ":ERROR",
		Text:      msg,
		Timestamp: time.Now(),
	}
}
