package assemblers

import (
	"fmt"
	"runtime"
	_debug "runtime/debug"
	"sync"
	"time"

	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/rs/zerolog/log"
)

type tcpStreamMap struct {
	streams  *sync.Map
	streamId int64
}

func NewTcpStreamMap() api.TcpStreamMap {
	return &tcpStreamMap{
		streams: &sync.Map{},
	}
}

func (streamMap *tcpStreamMap) Range(f func(key, value interface{}) bool) {
	streamMap.streams.Range(f)
}

func (streamMap *tcpStreamMap) Store(key, value interface{}) {
	streamMap.streams.Store(key, value)
	diagnose.AppStats.IncLiveTcpStreams()
}

func (streamMap *tcpStreamMap) Delete(key interface{}) {
	streamMap.streams.Delete(key)
	diagnose.AppStats.DecLiveTcpStreams()
}

func (streamMap *tcpStreamMap) NextId() int64 {
	streamMap.streamId++
	return streamMap.streamId
}

func (streamMap *tcpStreamMap) CloseTimedoutTcpStreamChannels() {
	tcpStreamChannelTimeoutMs := GetTcpChannelTimeoutMs()
	closeTimedoutTcpChannelsIntervalMs := GetCloseTimedoutTcpChannelsInterval()
	log.Info().
		Msg(fmt.Sprintf(
			"Using %d ms as the close timed out TCP stream channels interval",
			closeTimedoutTcpChannelsIntervalMs/time.Millisecond,
		))

	ticker := time.NewTicker(closeTimedoutTcpChannelsIntervalMs)
	for {
		<-ticker.C

		_debug.FreeOSMemory()
		streamMap.streams.Range(func(key interface{}, value interface{}) bool {
			// `*tlsStream` is not yet applicable to this routine.
			// So, we cast into `(*tcpStream)` and ignore `*tlsStream`
			stream, ok := value.(*tcpStream)
			if !ok {
				return true
			}

			stream.Lock()
			protocol := stream.protocol
			isClosed := stream.isClosed
			stream.Unlock()

			if protocol == nil {
				if !isClosed && time.Now().After(stream.createdAt.Add(tcpStreamChannelTimeoutMs)) {
					stream.close()
					diagnose.AppStats.IncDroppedTcpStreams()
					log.Debug().
						Msg(fmt.Sprintf(
							"Dropped an unidentified TCP stream because of timeout. Total dropped: %d Total Goroutines: %d Timeout (ms): %d",
							diagnose.AppStats.DroppedTcpStreams,
							runtime.NumGoroutine(),
							tcpStreamChannelTimeoutMs/time.Millisecond,
						))
				}
			}
			return true
		})
	}
}
