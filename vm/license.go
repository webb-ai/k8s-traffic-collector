package vm

import (
	"fmt"
)

const licenseErrorMsgFormat = "%s helper requires Pro license! Please visit https://kubeshark.co/pro"

func protectLicense(helperName string, scriptIndex int64, license bool) bool {
	if !license {
		SendLogError(scriptIndex, fmt.Sprintf(licenseErrorMsgFormat, helperName))

		return true
	}

	return false
}
