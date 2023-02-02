package vm

import (
	"net/http"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

func defineWebhook(o *otto.Otto) {
	err := o.Set("webhook", func(call otto.FunctionCall) otto.Value {
		method := call.Argument(0).String()
		url := call.Argument(1).String()
		body := call.Argument(2).String()

		client := &http.Client{}
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			log.Error().Err(err).Send()
		}

		_, err = client.Do(req)
		if err != nil {
			log.Error().Err(err).Send()
		}

		return otto.UndefinedValue()
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineConsole(o *otto.Otto, logChannel chan *Log, key int64) {
	err := o.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			text := call.Argument(0).String()

			logChannel <- &Log{
				Script:    key,
				Suffix:    "",
				Text:      text,
				Timestamp: time.Now(),
			}

			return otto.UndefinedValue()
		},
		"error": func(call otto.FunctionCall) otto.Value {
			text := call.Argument(0).String()

			logChannel <- &Log{
				Script:    key,
				Suffix:    ":ERROR",
				Text:      text,
				Timestamp: time.Now(),
			}

			return otto.UndefinedValue()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineHelpers(otto *otto.Otto, logChannel chan *Log, key int64) {
	defineWebhook(otto)
	defineConsole(otto, logChannel, key)
}
