package misc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

const NameResolutionHistoryFilename string = "name_resolution_history.json"

var dataDir = "data"

func InitDataDir() {
	body, err := os.ReadFile("/etc/machine-id")
	newDataDir := dataDir
	if err == nil {
		machineId := strings.TrimSpace(string(body))
		log.Info().Str("id", machineId).Msg("Machine ID is:")
		newDataDir = fmt.Sprintf("%s/%s", dataDir, machineId)
	}

	err = os.MkdirAll(newDataDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("data-dir", newDataDir).Msg("Unable to create the new data directory:")
	} else {
		dataDir = newDataDir
		log.Info().Str("data-dir", dataDir).Msg("Set the data directory to:")
	}

	pcapsDir := GetPcapsDir()
	err = os.MkdirAll(pcapsDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("pcaps-dir", pcapsDir).Msg("Unable to create the new pcaps directory:")
	}
}

func GetDataDir() string {
	return dataDir
}

func GetDataPath(path string) string {
	return fmt.Sprintf("%s/%s", GetDataDir(), path)
}

func RemoveDataDir(path string) string {
	return strings.TrimLeft(path, fmt.Sprintf("%s/", GetDataDir()))
}

func GetPcapsDir() string {
	return GetDataPath("pcaps")
}

func GetPcapPath(id string) string {
	return fmt.Sprintf("%s/%s", GetPcapsDir(), id)
}

func BuildPcapPath(id int64) string {
	return fmt.Sprintf("%s/%012d.pcap", GetPcapsDir(), id)
}

func BuildTmpPcapPath(id int64) string {
	return fmt.Sprintf("%stmp", BuildPcapPath(id))
}

func BuildTlsPcapPath(id int64) string {
	return fmt.Sprintf("%s/%012d_tls.pcap", GetPcapsDir(), id)
}

func BuildTlsTmpPcapPath(id int64) string {
	return fmt.Sprintf("%stmp", BuildTlsPcapPath(id))
}

func BuildUdpPcapPath(id int64) string {
	return fmt.Sprintf("%s/%012d_udp.pcap", GetPcapsDir(), id)
}

func CleanUpTmpPcaps() error {
	pcapFiles, err := os.ReadDir(GetPcapsDir())
	if err != nil {
		return err
	}

	for _, pcap := range pcapFiles {
		if filepath.Ext(pcap.Name()) == ".pcaptmp" {
			err = os.Remove(GetPcapPath(pcap.Name()))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func GetNameResolutionHistoryPath() string {
	return fmt.Sprintf("%s/%s", GetDataDir(), NameResolutionHistoryFilename)
}

func IsTls(id string) bool {
	return strings.HasSuffix(id[:len(id)-len(filepath.Ext(id))], "_tls")
}
