package vm

import (
	"fmt"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket"
	"github.com/rs/zerolog/log"
)

// Hook: capturedItem, does not accept returns
func CapturedItemHook(entry *api.Entry) {
	hook := "capturedItem"

	data, err := MarshalUnmarshalEntry(entry)
	if err != nil {
		log.Error().Err(err).Send()
		return
	}

	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		if entry == nil {
			return true
		}
		v.Lock()
		_, err := v.Otto.Call(hook, nil, data)
		v.Unlock()
		if err != nil {
			if !IsMissingHookError(err, hook) {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
			}
		}
		return true
	})
}

// Hook: capturedPacket, does not accept returns
func CapturedPacketHook(packet gopacket.Packet) {
	hook := "capturedPacket"
	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		info, err := BuildCustomPacketInfo(packet)
		if err != nil {
			log.Debug().Err(err).Send()
			return true
		}

		v.Lock()
		_, err = v.Otto.Call(hook, nil, info)
		v.Unlock()
		if err != nil {
			if !IsMissingHookError(err, hook) {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
			}
		}
		return true
	})
}

// Hook: queriedItem, accepts Object type returns
func QueriedItemHook(entry *api.Entry) *api.Entry {
	returnedEntry := entry

	data, err := MarshalUnmarshalEntry(entry)
	if err != nil {
		log.Error().Err(err).Send()
		return nil
	}

	hook := "queriedItem"
	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		if entry == nil {
			return true
		}
		v.Lock()
		ottoValue, err := v.Otto.Call(hook, nil, data)
		v.Unlock()
		if err != nil {
			if !IsMissingHookError(err, hook) {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
			}
			return true
		}

		if ottoValue.IsObject() {
			newAlteredEntry, err := ottoValue.Export()
			if err != nil {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
				return true
			}

			convertedEntry, err := MarshalUnmarshalEntryReverse(newAlteredEntry.(map[string]interface{}))
			if err != nil {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
				return true
			}

			returnedEntry = convertedEntry
		}

		return true
	})

	return returnedEntry
}

// Hook: passedJob, does not accept returns
func PassedJobHook(tag string, cron string, limit int64) {
	hook := "passedJob"

	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		v.Lock()
		_, err := v.Otto.Call(hook, nil, tag, cron, limit)
		v.Unlock()
		if err != nil {
			if !IsMissingHookError(err, hook) {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
			}
		}
		return true
	})
}

// Hook: failedJob, does not accept returns
func FailedJobHook(tag string, cron string, limit int64, err string) {
	hook := "failedJob"

	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		v.Lock()
		_, err := v.Otto.Call(hook, nil, tag, cron, limit, err)
		v.Unlock()
		if err != nil {
			if !IsMissingHookError(err, hook) {
				SendLogError(key.(int64), fmt.Sprintf("(hook=%s) %s", hook, err.Error()))
			}
		}
		return true
	})
}
