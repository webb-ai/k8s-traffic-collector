package vm

import (
	"net/http"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

const HttpRequestTimeoutSecond = 5

func defineWebhook(o *otto.Otto, logChannel chan *Log, scriptIndex int64, license bool) {
	helperName := "webhook"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, logChannel, scriptIndex, license) {
			return returnValue
		}

		method := call.Argument(0).String()
		url := call.Argument(1).String()
		body := call.Argument(2).String()

		client := &http.Client{
			Transport: &http.Transport{
				MaxConnsPerHost:   1,
				DisableKeepAlives: true,
			},
			Timeout: time.Duration(HttpRequestTimeoutSecond) * time.Second,
		}
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			log.Error().Err(err).Send()
			return returnValue
		}

		_, err = client.Do(req)
		if err != nil {
			log.Error().Err(err).Send()
			return returnValue
		}

		return returnValue
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineConsole(o *otto.Otto, logChannel chan *Log, scriptIndex int64) {
	err := o.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			text := call.Argument(0).String()

			logChannel <- &Log{
				Script:    scriptIndex,
				Suffix:    "",
				Text:      text,
				Timestamp: time.Now(),
			}

			return otto.UndefinedValue()
		},
		"error": func(call otto.FunctionCall) otto.Value {
			text := call.Argument(0).String()

			logChannel <- &Log{
				Script:    scriptIndex,
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

func defineHelpers(otto *otto.Otto, logChannel chan *Log, scriptIndex int64, license bool) {
	defineWebhook(otto, logChannel, scriptIndex, license)
	defineConsole(otto, logChannel, scriptIndex)
}
