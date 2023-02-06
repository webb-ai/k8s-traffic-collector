package vm

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kubeshark/worker/utils"
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

const HttpRequestTimeoutSecond = 5

func defineWebhook(o *otto.Otto, scriptIndex int64, license bool) {
	helperName := "webhook"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
			return returnValue
		}

		method := call.Argument(0).String()
		url := call.Argument(1).String()
		body := call.Argument(2).String()

		client := &http.Client{}
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			SendLogError(scriptIndex, err.Error())
			return returnValue
		}

		_, err = client.Do(req)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
			return returnValue
		}

		return returnValue
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineConsole(o *otto.Otto, scriptIndex int64) {
	err := o.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			SendLog(scriptIndex, ArgumentListToString(call.ArgumentList))

			return otto.UndefinedValue()
		},
		"error": func(call otto.FunctionCall) otto.Value {
			SendLogError(scriptIndex, ArgumentListToString(call.ArgumentList))

			return otto.UndefinedValue()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func definePass(o *otto.Otto, scriptIndex int64) {
	err := o.Set("pass", func(call otto.FunctionCall) otto.Value {
		obj := call.Argument(0).Object()

		err := obj.Set("passed", true)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
		}

		return obj.Value()
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineFail(o *otto.Otto, scriptIndex int64) {
	err := o.Set("fail", func(call otto.FunctionCall) otto.Value {
		obj := call.Argument(0).Object()

		err := obj.Set("failed", true)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
		}

		return obj.Value()
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineSlack(o *otto.Otto, scriptIndex int64, license bool) {
	helperName := "slack"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
			return returnValue
		}

		token := call.Argument(0).String()
		channelId := call.Argument(1).String()
		pretext := call.Argument(2).String()
		text := call.Argument(3).String()
		color := call.Argument(4).String()

		client := slack.New(token, slack.OptionDebug(false))

		attachment := slack.Attachment{
			Pretext: pretext,
			Text:    text,
			Color:   color,
			Fields: []slack.AttachmentField{
				{
					Title: "Timestamp",
					Value: time.Now().String(),
				},
			},
		}

		_, timestamp, err := client.PostMessage(
			channelId,
			slack.MsgOptionAttachments(attachment),
		)

		if err != nil {
			SendLogError(scriptIndex, err.Error())
		} else {
			secs, nanos, err := utils.ParseSeconds(timestamp)
			if err != nil {
				log.Error().Err(err).Send()
				return returnValue
			}
			SendLog(scriptIndex, fmt.Sprintf("Message sent to Slack channel: %s at %s", channelId, time.Unix(secs, nanos).UTC()))
		}

		return returnValue
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineHelpers(otto *otto.Otto, scriptIndex int64, license bool) {
	defineWebhook(otto, scriptIndex, license)
	defineConsole(otto, scriptIndex)
	definePass(otto, scriptIndex)
	defineFail(otto, scriptIndex)
	defineSlack(otto, scriptIndex, license)
}
