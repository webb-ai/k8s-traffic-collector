package extensions

import (
	"sort"

	"github.com/kubeshark/worker/pkg/api"
	amqpExt "github.com/kubeshark/worker/pkg/extensions/amqp"
	dnsExt "github.com/kubeshark/worker/pkg/extensions/dns"
	httpExt "github.com/kubeshark/worker/pkg/extensions/http"
	kafkaExt "github.com/kubeshark/worker/pkg/extensions/kafka"
	redisExt "github.com/kubeshark/worker/pkg/extensions/redis"
)

var (
	Extensions    []*api.Extension          // global
	ExtensionsMap map[string]*api.Extension // global
)

func LoadExtensions() {
	Extensions = make([]*api.Extension, 0)
	ExtensionsMap = make(map[string]*api.Extension)

	extensionHttp := &api.Extension{}
	dissectorHttp := httpExt.NewDissector()
	dissectorHttp.Register(extensionHttp)
	extensionHttp.Dissector = dissectorHttp
	Extensions = append(Extensions, extensionHttp)
	ExtensionsMap[extensionHttp.Protocol.Name] = extensionHttp

	extensionAmqp := &api.Extension{}
	dissectorAmqp := amqpExt.NewDissector()
	dissectorAmqp.Register(extensionAmqp)
	extensionAmqp.Dissector = dissectorAmqp
	Extensions = append(Extensions, extensionAmqp)
	ExtensionsMap[extensionAmqp.Protocol.Name] = extensionAmqp

	extensionKafka := &api.Extension{}
	dissectorKafka := kafkaExt.NewDissector()
	dissectorKafka.Register(extensionKafka)
	extensionKafka.Dissector = dissectorKafka
	Extensions = append(Extensions, extensionKafka)
	ExtensionsMap[extensionKafka.Protocol.Name] = extensionKafka

	extensionRedis := &api.Extension{}
	dissectorRedis := redisExt.NewDissector()
	dissectorRedis.Register(extensionRedis)
	extensionRedis.Dissector = dissectorRedis
	Extensions = append(Extensions, extensionRedis)
	ExtensionsMap[extensionRedis.Protocol.Name] = extensionRedis

	extensionDns := &api.Extension{}
	dissectorDns := dnsExt.NewDissector()
	dissectorDns.Register(extensionDns)
	extensionDns.Dissector = dissectorDns
	Extensions = append(Extensions, extensionDns)
	ExtensionsMap[extensionDns.Protocol.Name] = extensionDns

	sort.Slice(Extensions, func(i, j int) bool {
		return Extensions[i].Protocol.Priority < Extensions[j].Protocol.Priority
	})
}
