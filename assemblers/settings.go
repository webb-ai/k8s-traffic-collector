package assemblers

import (
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	ProfilingEnabledEnvVarName                     = "PROFILING_ENABLED"
	ProfilingDumpPath                              = "PROFILING_DUMP_PATH"
	ProfilingTimeIntervalSeconds                   = "PROFILING_INTERVAL_SECONDS"
	MaxBufferedPagesTotalEnvVarName                = "MAX_BUFFERED_PAGES_TOTAL"
	MaxBufferedPagesPerConnectionEnvVarName        = "MAX_BUFFERED_PAGES_PER_CONNECTION"
	MaxBufferedPagesTotalDefaultValue              = 5000
	MaxBufferedPagesPerConnectionDefaultValue      = 5000
	TcpStreamChannelTimeoutMsEnvVarName            = "TCP_STREAM_CHANNEL_TIMEOUT_MS"
	TcpStreamChannelTimeoutMsDefaultValue          = 10000
	CloseTimedoutTcpChannelsIntervalMsEnvVarName   = "CLOSE_TIMEDOUT_TCP_STREAM_CHANNELS_INTERVAL_MS"
	CloseTimedoutTcpChannelsIntervalMsDefaultValue = 1000
	CloseTimedoutTcpChannelsIntervalMsMinValue     = 10
	CloseTimedoutTcpChannelsIntervalMsMaxValue     = 10000
)

func GetMaxBufferedPagesTotal() int {
	valueFromEnv, err := strconv.Atoi(os.Getenv(MaxBufferedPagesTotalEnvVarName))
	if err != nil {
		return MaxBufferedPagesTotalDefaultValue
	}
	return valueFromEnv
}

func GetMaxBufferedPagesPerConnection() int {
	valueFromEnv, err := strconv.Atoi(os.Getenv(MaxBufferedPagesPerConnectionEnvVarName))
	if err != nil {
		return MaxBufferedPagesPerConnectionDefaultValue
	}
	return valueFromEnv
}

func GetProfilingEnabled() bool {
	return os.Getenv(ProfilingEnabledEnvVarName) != ""
}

func GetTcpChannelTimeoutMs() time.Duration {
	valueFromEnv, err := strconv.Atoi(os.Getenv(TcpStreamChannelTimeoutMsEnvVarName))
	if err != nil {
		return TcpStreamChannelTimeoutMsDefaultValue * time.Millisecond
	}
	return time.Duration(valueFromEnv) * time.Millisecond
}

func GetCloseTimedoutTcpChannelsInterval() time.Duration {
	defaultDuration := CloseTimedoutTcpChannelsIntervalMsDefaultValue * time.Millisecond
	rangeMin := CloseTimedoutTcpChannelsIntervalMsMinValue
	rangeMax := CloseTimedoutTcpChannelsIntervalMsMaxValue
	closeTimedoutTcpChannelsIntervalMsStr := os.Getenv(CloseTimedoutTcpChannelsIntervalMsEnvVarName)
	if closeTimedoutTcpChannelsIntervalMsStr == "" {
		return defaultDuration
	} else {
		closeTimedoutTcpChannelsIntervalMs, err := strconv.Atoi(closeTimedoutTcpChannelsIntervalMsStr)
		if err != nil {
			log.Error().Err(err).Str("env-var", CloseTimedoutTcpChannelsIntervalMsEnvVarName).Msg("While parsing environment variable!")
			return defaultDuration
		} else {
			if closeTimedoutTcpChannelsIntervalMs < rangeMin || closeTimedoutTcpChannelsIntervalMs > rangeMax {
				log.Error().Err(err).Str("env-var", CloseTimedoutTcpChannelsIntervalMsEnvVarName).Int("min", rangeMin).Int("max", rangeMax).Msg("The value of environment variable is not in acceptable range!")
				return defaultDuration
			} else {
				return time.Duration(closeTimedoutTcpChannelsIntervalMs) * time.Millisecond
			}
		}
	}
}
