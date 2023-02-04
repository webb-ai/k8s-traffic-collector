package vm

import (
	"fmt"
	"time"
)

const licenseErrorMsgFormat = "%s helper requires Pro license! Please visit https://kubeshark.co/pro"

func protectLicense(helperName string, logChannel chan *Log, scriptIndex int64, license bool) bool {
	if !license {
		text := fmt.Sprintf(licenseErrorMsgFormat, helperName)
		logChannel <- &Log{
			Script:    scriptIndex,
			Suffix:    ":ERROR",
			Text:      text,
			Timestamp: time.Now(),
		}

		return true
	}

	return false
}
