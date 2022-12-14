package controllers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/mergecap"
	"github.com/kubeshark/worker/misc/replay"
	"github.com/rs/zerolog/log"
)

func GetTotalTcpStreams(c *gin.Context) {
	dataDir := misc.GetDataDir()
	pcapFiles, err := os.ReadDir(dataDir)
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	var counter int64
	for _, pcap := range pcapFiles {
		if filepath.Ext(pcap.Name()) != ".pcap" {
			continue
		}

		counter++
	}

	c.JSON(http.StatusOK, gin.H{
		"total": counter,
	})
}

func GetMerge(c *gin.Context) {
	dataDir := misc.GetDataDir()
	pcapFiles, err := os.ReadDir(dataDir)
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	outFile, err := os.CreateTemp(dataDir, "mergecap")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create the out file for PCAP merger!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer outFile.Close()
	defer os.Remove(outFile.Name())

	err = mergecap.Mergecap(pcapFiles, outFile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to merge the PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	attachmentName := fmt.Sprintf("%d.pcap", time.Now().UnixNano())

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+attachmentName)
	c.Header("Content-Type", "application/octet-stream")
	c.File(outFile.Name())
}

func GetReplay(c *gin.Context) {
	_id := c.Param("id")
	idIndex := strings.Split(_id, "-")
	if len(idIndex) < 2 {
		msg := "Malformed ID!"
		log.Error().Str("id", _id).Msg(msg)
		misc.HandleError(c, fmt.Errorf(msg))
		return
	}
	id := idIndex[0]

	filepath := misc.GetPcapPath(id)
	err := replay.Replay(filepath, replay.DefaultRouteInterface(""))
	if err != nil {
		log.Error().Str("path", filepath).Err(err).Msg("Couldn't replay the PCAP:")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
	})
}
