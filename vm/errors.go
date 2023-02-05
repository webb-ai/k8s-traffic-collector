package vm

import (
	"fmt"

	"github.com/robertkrimen/otto"
)

func IsMissingHookError(err error, hook string) bool {
	_, ok := err.(*otto.Error)
	if !ok {
		return false
	}

	if err.Error() == fmt.Sprintf("ReferenceError: '%s' is not defined", hook) {
		return true
	}

	return false
}
