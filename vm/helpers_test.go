package vm

import (
	"testing"
)

func TestWebhookHelper(t *testing.T) {
	var key int64 = 0
	code := `
function capturedItem(item) {
	webhook("POST", "https://webhook.site/fd14dd50-980c-40d0-bd82-63b7807ac589", "hello world");
}

`
	logChannel := make(chan *Log)

	v, err := Create(key, code, logChannel, true)
	if err != nil {
		panic(err)
	}

	hook := "capturedItem"
	for i := 0; i < 5; i++ {
		_, err = v.Otto.Call(hook, nil, nil)
		if err != nil {
			panic(err)
		}
	}
}
