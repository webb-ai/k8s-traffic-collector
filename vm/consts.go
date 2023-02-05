package vm

import (
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

var consts map[string]interface{}

func SetConsts(c map[string]interface{}) {
	consts = c
}

func defineConsts(otto *otto.Otto) {
	for key, value := range consts {
		err := otto.Set(key, value)
		if err != nil {
			log.Error().Err(err).Send()
		}
	}
}
