package controllers

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/mergecap"
	"github.com/kubeshark/worker/misc/replay"
	"github.com/rs/zerolog/log"
)

func GetTotalSize(c *gin.Context) {
	fileInfo, err := os.Stat(misc.GetMasterPcapPath())
	if err != nil {
		log.Error().Err(err).Send()
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total": fileInfo.Size(),
	})
}

func GetDownloadPcap(c *gin.Context) {
	id := c.Param("id")
	context := c.Query("c")

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+id)
	c.Header("Content-Type", "application/octet-stream")
	c.File(misc.GetPcapPath(id, context))
}

type postMergeRequest struct {
	Query   string   `json:"query"`
	Context string   `json:"context"`
	Pcaps   []string `json:"pcaps"`
}

func PostMerge(c *gin.Context) {
	var req postMergeRequest
	if err := c.Bind(&req); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	pcapsDir := misc.GetContextPath(req.Context)
	pcapFiles, err := os.ReadDir(pcapsDir)
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	outFile, err := os.CreateTemp(pcapsDir, "mergecap")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create the out file for PCAP merger!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer outFile.Close()
	defer os.Remove(outFile.Name())

	err = mergecap.Mergecap(pcapFiles, req.Query, req.Pcaps, outFile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to merge the PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	attachmentName := fmt.Sprintf("%d.pcap", time.Now().Unix())

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+attachmentName)
	c.Header("Content-Type", "application/octet-stream")
	c.File(outFile.Name())
}

func GetReplay(c *gin.Context) {
	id := c.Param("id")
	context := c.Query("c")

	count, err := strconv.ParseUint(c.Query("count"), 0, 64)
	if err != nil {
		count = 1
	}

	delay, err := strconv.ParseUint(c.Query("delay"), 0, 64)
	if err != nil {
		delay = 100
	}

	host := c.Query("host")
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"host": host,
			"msg":  "Destination host is empty. Set `host` query parameter.",
		})
		return
	}

	port := c.Query("port")
	if port == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"port": port,
			"msg":  "Destination port is empty. Set `port` query parameter.",
		})
		return
	}

	concurrency := true
	concurrent := c.Query("concurrent")
	if concurrent == "" || concurrent == "false" {
		concurrency = false
	}

	pcapPath := misc.GetPcapPath(id, context)
	err = replay.Replay(pcapPath, host, port, count, delay, concurrency)
	if err != nil {
		log.Error().Str("path", pcapPath).Err(err).Msg("Couldn't replay the PCAP:")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
	})
}

func GetNameResolutionHistory(c *gin.Context) {
	m := resolver.K8sResolver.GetDumpNameResolutionHistoryMap()
	c.JSON(http.StatusOK, m)
}
