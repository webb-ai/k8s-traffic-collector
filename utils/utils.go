package utils

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/worker/kubernetes/resolver"
)

func ItemToEntry(item *api.OutputChannelItem) *api.Entry {
	extension := extensions.ExtensionsMap[item.Protocol.Name]

	resolvedSource, resolvedDestination := resolveIP(item.ConnectionInfo, item.Timestamp)

	return extension.Dissector.Analyze(item, resolvedSource, resolvedDestination)
}

func SummarizeEntry(entry *api.Entry) *api.BaseEntry {
	extension := extensions.ExtensionsMap[entry.Protocol.Name]

	return extension.Dissector.Summarize(entry)
}

func resolveIP(connectionInfo *api.ConnectionInfo, timestamp int64) (resolvedSource *api.Resolution, resolvedDestination *api.Resolution) {
	if resolver.K8sResolver != nil {
		unresolvedSource := connectionInfo.ClientIP
		resolvedSource = resolver.K8sResolver.Resolve(unresolvedSource, timestamp)
		if resolvedSource == nil {
			resolvedSource = &api.Resolution{
				IP:   connectionInfo.ClientIP,
				Port: connectionInfo.ClientPort,
			}
		}

		unresolvedDestination := fmt.Sprintf("%s:%s", connectionInfo.ServerIP, connectionInfo.ServerPort)
		resolvedDestination = resolver.K8sResolver.Resolve(unresolvedDestination, timestamp)

		if resolvedDestination == nil {
			resolvedDestination = &api.Resolution{
				IP:   connectionInfo.ServerIP,
				Port: connectionInfo.ServerPort,
			}
		}
	}
	return
}

func ParseSeconds(secs string) (int64, int64, error) {
	// "789.0123" => []string{"789", "0123"}
	parts := strings.Split(secs, ".")
	if len(parts) > 2 {
		return 0, 0, errors.New("could not parse as seconds")
	} else if len(parts) < 2 {
		// no nanoseconds, just seconds
		// "789" => []string{"789"}
		s, err := strconv.ParseInt(parts[0], 10, 64)
		return s, 0, err
	}

	// convert the second's part
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if nil != err {
		return 0, 0, err
	}

	// the multiply approach
	// (nanoseconds have at most 9 digits)
	nanos := parts[1]
	n := len(nanos)
	if n > 9 {
		// truncate nanos to 9 digits
		// 0.0123456789 => 0.012345678
		nanos = nanos[:9]
		n = 9
	}
	mult := int64(math.Pow10(9 - n))

	nano, err := strconv.ParseInt(nanos, 10, 64)
	if nil != err {
		return 0, 0, err
	}

	return s, nano * mult, nil
}
