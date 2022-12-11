package controllers

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/misc"
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

	c.JSON(http.StatusOK, gin.H{
		"total": len(pcapFiles),
	})
}
