package vm

import (
	"fmt"
)

const licenseErrorMsgFormat = "%s helper requires PRO license! Please visit https://kubeshark.co/pricing"

var license bool

func protectLicense(helperName string, scriptIndex int64) bool {
	if !license {
		SendLogError(scriptIndex, fmt.Sprintf(licenseErrorMsgFormat, helperName))

		return true
	}

	return false
}

func SetLicense(v bool) {
	license = v
}
