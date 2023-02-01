package utils

import (
	"fmt"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/rs/zerolog/log"
)

func ItemToEntry(item *api.OutputChannelItem) *api.Entry {
	extension := extensions.ExtensionsMap[item.Protocol.Name]

	resolvedSource, resolvedDestination, namespace := resolveIP(item.ConnectionInfo, item.Timestamp)

	if namespace == "" && item.Namespace != api.UnknownNamespace {
		namespace = item.Namespace
	}

	return extension.Dissector.Analyze(item, resolvedSource, resolvedDestination, namespace)
}

func SummarizeEntry(entry *api.Entry) *api.BaseEntry {
	extension := extensions.ExtensionsMap[entry.Protocol.Name]

	return extension.Dissector.Summarize(entry)
}

func resolveIP(connectionInfo *api.ConnectionInfo, timestamp int64) (resolvedSource string, resolvedDestination string, namespace string) {
	if resolver.K8sResolver != nil {
		unresolvedSource := connectionInfo.ClientIP
		resolvedSourceObject := resolver.K8sResolver.Resolve(unresolvedSource, timestamp)
		if resolvedSourceObject == nil {
			log.Debug().Str("source", unresolvedSource).Msg("Cannot find resolved name!")
		} else {
			resolvedSource = resolvedSourceObject.FullAddress
			namespace = resolvedSourceObject.Namespace
		}

		unresolvedDestination := fmt.Sprintf("%s:%s", connectionInfo.ServerIP, connectionInfo.ServerPort)
		resolvedDestinationObject := resolver.K8sResolver.Resolve(unresolvedDestination, timestamp)
		if resolvedDestinationObject == nil {
			unresolvedDestination = connectionInfo.ServerIP
			resolvedDestinationObject = resolver.K8sResolver.Resolve(unresolvedDestination, timestamp)
		}

		if resolvedDestinationObject == nil {
			log.Debug().Str("destination", unresolvedDestination).Msg("Cannot find resolved name!")
		} else {
			resolvedDestination = resolvedDestinationObject.FullAddress
			// Overwrite namespace (if it was set according to the source)
			// Only overwrite if non-empty
			if resolvedDestinationObject.Namespace != "" {
				namespace = resolvedDestinationObject.Namespace
			}
		}
	}
	return resolvedSource, resolvedDestination, namespace
}
