package vm

import (
	"net/http"
	"strings"

	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

func defineWebhookHelper(o *otto.Otto) {
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

		return otto.Value{}
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineHelpers(otto *otto.Otto) {
	defineWebhookHelper(otto)
}
