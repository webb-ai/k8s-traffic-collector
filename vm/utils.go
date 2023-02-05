package vm

import "github.com/robertkrimen/otto"

func ArgumentListToString(args []otto.Value) (text string) {
	for _, arg := range args {
		if len(text) == 0 {
			text += ""
		}

		text += arg.String()
	}

	return
}
