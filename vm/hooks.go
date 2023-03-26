package vm

import (
	"fmt"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket"
	"github.com/rs/zerolog/log"
)

// Hook: onItemCaptured, does not accept returns
func ItemCapturedHook(entry *api.Entry) {
	hook := "onItemCaptured"

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

// Hook: onPacketCaptured, does not accept returns
func PacketCapturedHook(packet gopacket.Packet, fragmented bool) {
	hook := "onPacketCaptured"
	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		info, err := BuildCustomPacketInfo(packet, fragmented)
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

// Hook: onItemQueried, accepts Object type returns
func ItemQueriedHook(entry *api.Entry) *api.Entry {
	returnedEntry := entry

	data, err := MarshalUnmarshalEntry(entry)
	if err != nil {
		log.Error().Err(err).Send()
		return nil
	}

	hook := "onItemQueried"
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

// Hook: onJobPassed, does not accept returns
func JobPassedHook(tag string, cron string, limit int64) {
	hook := "onJobPassed"

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

// Hook: onJobFailed, does not accept returns
func JobFailedHook(tag string, cron string, limit int64, err string) {
	hook := "onJobFailed"

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
