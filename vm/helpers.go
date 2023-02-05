package vm

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
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

		client := &http.Client{
			Transport: &http.Transport{
				MaxConnsPerHost:   1,
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(HttpRequestTimeoutSecond) * time.Second,
		}
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

func defineHelpers(otto *otto.Otto, scriptIndex int64, license bool) {
	defineWebhook(otto, scriptIndex, license)
	defineConsole(otto, scriptIndex)
	definePass(otto, scriptIndex)
	defineFail(otto, scriptIndex)
}
