package tracer

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"

	"github.com/cilium/ebpf/perf"
	"github.com/go-errors/errors"
)

const logPrefix = "[bpf] "

// The same consts defined in log.h
var logLevels = map[int]string{
	0: "ERROR",
	1: "INFO",
	2: "DEBUG",
}

type logMessage struct {
	Level       uint32
	MessageCode uint32
	Arg1        uint64
	Arg2        uint64
	Arg3        uint64
}

type bpfLogger struct {
	logReader *perf.Reader
}

func newBpfLogger() *bpfLogger {
	return &bpfLogger{
		logReader: nil,
	}
}

func (p *bpfLogger) init(bpfObjects *tracerObjects, bufferSize int) error {
	var err error

	p.logReader, err = perf.NewReader(bpfObjects.LogBuffer, bufferSize)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	return nil
}

func (p *bpfLogger) close() error {
	return p.logReader.Close()
}

func (p *bpfLogger) poll() {
	log.Printf("Start polling for bpf logs")

	for {
		record, err := p.logReader.Read()

		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			LogError(errors.Errorf("Error reading from bpf logger perf buffer, aboring logger! %w", err))
			return
		}

		if record.LostSamples != 0 {
			log.Printf("Log buffer is full, dropped %d logs", record.LostSamples)
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var log logMessage

		if err := binary.Read(buffer, binary.LittleEndian, &log); err != nil {
			LogError(errors.Errorf("Error parsing log %v", err))
			continue
		}

		p.log(&log)
	}
}

func (p *bpfLogger) log(msg *logMessage) {
	if int(msg.MessageCode) >= len(bpfLogMessages) {
		log.Printf("Unknown message code from bpf logger %d", msg.MessageCode)
		return
	}

	format := bpfLogMessages[msg.MessageCode]
	tokensCount := strings.Count(format, "%")

	if tokensCount == 0 {
		log.Printf(logPrefix + logLevels[int(msg.Level)] + " " + format)
	} else if tokensCount == 1 {
		log.Printf(logPrefix+logLevels[int(msg.Level)]+" "+format, msg.Arg1)
	} else if tokensCount == 2 {
		log.Printf(logPrefix+logLevels[int(msg.Level)]+" "+format, msg.Arg1, msg.Arg2)
	} else if tokensCount == 3 {
		log.Printf(logPrefix+logLevels[int(msg.Level)]+" "+format, msg.Arg1, msg.Arg2, msg.Arg3)
	}
}
