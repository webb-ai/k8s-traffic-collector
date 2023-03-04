package vm

import (
	"fmt"
)

const licenseErrorMsgFormat = "%s helper requires Pro license! Please visit https://kubeshark.co/pro"

var license bool

func protectLicense(helperName string, scriptIndex int64) bool {
	if license {
		SendLogError(scriptIndex, fmt.Sprintf(licenseErrorMsgFormat, helperName))

		return true
	}

	return false
}

func SetLicense(v bool) {
	license = v
}
