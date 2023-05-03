package vm

import (
	"testing"

	"github.com/kubeshark/worker/misc"
)

func TestWebhookHelper(t *testing.T) {
	var key int64 = 0
	code := `
function onItemCaptured(item) {
	webhook("POST", "https://webhook.site/fd14dd50-980c-40d0-bd82-63b7807ac589", "hello world");
}

`
	LogGlobal = &LogState{
		Channel: make(chan *Log, misc.LogChannelBufferSize),
	}

	v, err := Create(key, code, "minikube", "192.168.1.1")
	if err != nil {
		panic(err)
	}

	hook := "onItemCaptured"
	for i := 0; i < 5; i++ {
		_, err = v.Otto.Call(hook, nil, nil)
		if err != nil {
			panic(err)
		}
	}
}
