package vm

import (
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

var env map[string]interface{}

func SetEnv(c map[string]interface{}) {
	env = c
}

func defineEnv(otto *otto.Otto) {
	var keys []string
	for key, value := range env {
		keys = append(keys, key)
		err := otto.Set(key, value)
		if err != nil {
			log.Error().Err(err).Send()
		}
	}

	err := otto.Set("env", keys)
	if err != nil {
		log.Error().Err(err).Send()
	}
}
