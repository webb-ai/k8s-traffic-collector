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
	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		if entry == nil {
			return true
		}
		v.Lock()
		_, err := v.Otto.Call(hook, nil, entry)
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
	hook := "queriedItem"
	Range(func(key, value interface{}) bool {
		v := value.(*VM)
		if entry == nil {
			return true
		}
		v.Lock()
		ottoValue, err := v.Otto.Call(hook, nil, entry)
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

			returnedEntry = newAlteredEntry.(*api.Entry)
		}

		return true
	})

	return returnedEntry
}
