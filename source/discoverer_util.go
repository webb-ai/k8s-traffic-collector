package source

import (
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

var numberRegex = regexp.MustCompile("[0-9]+")

func getSingleValueFromEnvironmentVariableFile(filePath string, variableName string) (string, error) {
	bytes, err := os.ReadFile(filePath)

	if err != nil {
		log.Warn().Err(err).Str("file", filePath).Msg("While reading environment file!")
		return "", err
	}

	envs := strings.Split(string(bytes), string([]byte{0}))

	for _, env := range envs {
		if !strings.Contains(env, "=") {
			continue
		}

		parts := strings.Split(env, "=")
		varName := parts[0]
		value := parts[1]

		if variableName == varName {
			return value, nil
		}
	}

	return "", nil
}
