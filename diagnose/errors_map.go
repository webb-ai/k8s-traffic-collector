package diagnose

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket/examples/util"
)

var TapErrors *errorsMap

type errorsMap struct {
	errorsMap      map[string]uint
	OutputLevel    int
	ErrorsCount    uint
	errorsMapMutex sync.Mutex
}

func InitializeErrorsMap(debug bool, verbose bool, quiet bool) {
	var outputLevel int

	defer util.Run()()
	if debug {
		outputLevel = 2
	} else if verbose {
		outputLevel = 1
	} else if quiet {
		outputLevel = -1
	}

	TapErrors = newErrorsMap(outputLevel)
}

func newErrorsMap(outputLevel int) *errorsMap {
	return &errorsMap{
		errorsMap:   make(map[string]uint),
		OutputLevel: outputLevel,
	}
}

/* minOutputLevel: Error will be printed only if outputLevel is above this value
 * t:              key for errorsMap (counting errors)
 * s, a:           arguments log.Printf
 * Note:           Too bad for perf that a... is evaluated
 */
func (e *errorsMap) logError(minOutputLevel int, t string, s string, a ...interface{}) {
	e.errorsMapMutex.Lock()
	e.ErrorsCount++
	nb := e.errorsMap[t]
	e.errorsMap[t] = nb + 1
	e.errorsMapMutex.Unlock()

	if e.OutputLevel >= minOutputLevel {
		formatStr := fmt.Sprintf("%s: %s", t, s)
		log.Printf(formatStr, a...)
	}
}

func (e *errorsMap) Error(t string, s string, a ...interface{}) {
	e.logError(0, t, s, a...)
}

func (e *errorsMap) SilentError(t string, s string, a ...interface{}) {
	e.logError(2, t, s, a...)
}

func (e *errorsMap) Debug(s string, a ...interface{}) {
	log.Printf(s, a...)
}

func (e *errorsMap) GetErrorsSummary() (int, string) {
	e.errorsMapMutex.Lock()
	errorMapLen := len(e.errorsMap)
	errorsSummery := fmt.Sprintf("%v", e.errorsMap)
	e.errorsMapMutex.Unlock()
	return errorMapLen, errorsSummery
}

func (e *errorsMap) PrintSummary() {
	log.Printf("Errors: %d", e.ErrorsCount)
	for t := range e.errorsMap {
		log.Printf(" %s:\t\t%d", e, e.errorsMap[t])
	}
}
