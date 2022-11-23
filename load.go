package tap

import (
	"sort"

	"github.com/kubeshark/worker/api"
	"github.com/kubeshark/worker/dbgctl"
	amqpExt "github.com/kubeshark/worker/extensions/amqp"
	httpExt "github.com/kubeshark/worker/extensions/http"
	kafkaExt "github.com/kubeshark/worker/extensions/kafka"
	redisExt "github.com/kubeshark/worker/extensions/redis"
)

var (
	Extensions    []*api.Extension          // global
	ExtensionsMap map[string]*api.Extension // global
	ProtocolsMap  map[string]*api.Protocol  //global
)

func loadExtensions() {
	Extensions = make([]*api.Extension, 0)
	ExtensionsMap = make(map[string]*api.Extension)
	ProtocolsMap = make(map[string]*api.Protocol)

	extensionHttp := &api.Extension{}
	dissectorHttp := httpExt.NewDissector()
	dissectorHttp.Register(extensionHttp)
	extensionHttp.Dissector = dissectorHttp
	Extensions = append(Extensions, extensionHttp)
	ExtensionsMap[extensionHttp.Protocol.Name] = extensionHttp
	protocolsHttp := dissectorHttp.GetProtocols()
	for k, v := range protocolsHttp {
		ProtocolsMap[k] = v
	}

	if !dbgctl.KubesharkTapperDisableNonHttpExtensions {
		extensionAmqp := &api.Extension{}
		dissectorAmqp := amqpExt.NewDissector()
		dissectorAmqp.Register(extensionAmqp)
		extensionAmqp.Dissector = dissectorAmqp
		Extensions = append(Extensions, extensionAmqp)
		ExtensionsMap[extensionAmqp.Protocol.Name] = extensionAmqp
		protocolsAmqp := dissectorAmqp.GetProtocols()
		for k, v := range protocolsAmqp {
			ProtocolsMap[k] = v
		}

		extensionKafka := &api.Extension{}
		dissectorKafka := kafkaExt.NewDissector()
		dissectorKafka.Register(extensionKafka)
		extensionKafka.Dissector = dissectorKafka
		Extensions = append(Extensions, extensionKafka)
		ExtensionsMap[extensionKafka.Protocol.Name] = extensionKafka
		protocolsKafka := dissectorKafka.GetProtocols()
		for k, v := range protocolsKafka {
			ProtocolsMap[k] = v
		}

		extensionRedis := &api.Extension{}
		dissectorRedis := redisExt.NewDissector()
		dissectorRedis.Register(extensionRedis)
		extensionRedis.Dissector = dissectorRedis
		Extensions = append(Extensions, extensionRedis)
		ExtensionsMap[extensionRedis.Protocol.Name] = extensionRedis
		protocolsRedis := dissectorRedis.GetProtocols()
		for k, v := range protocolsRedis {
			ProtocolsMap[k] = v
		}
	}

	sort.Slice(Extensions, func(i, j int) bool {
		return Extensions[i].Protocol.Priority < Extensions[j].Protocol.Priority
	})
}
