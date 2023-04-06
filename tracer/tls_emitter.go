package tracer

import (
	"github.com/kubeshark/worker/pkg/api"
)

type tlsEmitter struct {
	delegate api.Emitter
}

func (e *tlsEmitter) Emit(item *api.OutputChannelItem) {
	e.delegate.Emit(item)
}
