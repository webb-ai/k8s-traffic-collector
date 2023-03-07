package vm

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

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

func FormatJobTag(tag string) string {
	return strings.ReplaceAll(strings.ToLower(tag), " ", "-")
}

func CopyFile(src string, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
}

func throw(value otto.Value, _ error) otto.Value {
	panic(value)
	return otto.UndefinedValue() // nolint
}

func throwError(call otto.FunctionCall, err error) otto.Value {
	return throw(call.Otto.Call("new Error", nil, err.Error()))
}
