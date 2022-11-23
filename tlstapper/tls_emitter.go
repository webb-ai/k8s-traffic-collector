package tlstapper

import "github.com/kubeshark/worker/api"

type tlsEmitter struct {
	delegate  api.Emitter
	namespace string
}

func (e *tlsEmitter) Emit(item *api.OutputChannelItem) {
	item.Namespace = e.namespace
	e.delegate.Emit(item)
}
