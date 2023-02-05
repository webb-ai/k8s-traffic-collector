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
	var keys []string
	for key, value := range consts {
		keys = append(keys, key)
		err := otto.Set(key, value)
		if err != nil {
			log.Error().Err(err).Send()
		}
	}

	err := otto.Set("CONSTS", keys)
	if err != nil {
		log.Error().Err(err).Send()
	}
}
