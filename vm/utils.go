package vm

import (
	"encoding/json"

	"github.com/kubeshark/base/pkg/api"
	"github.com/robertkrimen/otto"
)

func ArgumentListToString(args []otto.Value) (text string) {
	for _, arg := range args {
		if len(text) != 0 {
			text += " "
		}

		text += arg.String()
	}

	return
}

func MarshalUnmarshalEntry(entry *api.Entry) (result map[string]interface{}, err error) {
	var data []byte
	data, err = json.Marshal(entry)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return
	}

	return
}

func MarshalUnmarshalEntryReverse(result map[string]interface{}) (entry *api.Entry, err error) {
	var data []byte
	data, err = json.Marshal(result)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &entry)
	if err != nil {
		return
	}

	return
}
