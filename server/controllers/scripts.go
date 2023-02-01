package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

type Script struct {
	Title string `json:"title"`
	Code  string `json:"code"`
}

func PutScript(c *gin.Context, logChannel chan *vm.Log) {
	var script Script
	if err := c.Bind(&script); err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	key := c.Param("key")
	i, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	v, err := vm.Create(i, script.Code, logChannel)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	vm.Set(i, v)

	c.JSON(http.StatusOK, gin.H{
		"key":    key,
		"script": script,
	})
}

func DeleteScript(c *gin.Context) {
	key := c.Param("key")
	i, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return
	}

	v, ok := vm.Get(i)
	if !ok {
		c.JSON(http.StatusNotFound, nil)
		return
	}

	close(v.LogChannel)

	vm.Delete(i)
}

func ScriptLogsHandler(c *gin.Context) {
	ws, err := websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set WebSocket upgrade:")
		return
	}
	defer ws.Close()

	vm.LogSockets = append(vm.LogSockets, ws)

	done := make(chan bool)
	<-done
}
