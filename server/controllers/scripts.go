package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

type Script struct {
	Title   string `json:"title"`
	Code    string `json:"code"`
	License bool   `json:"license"`
}

func PutScript(c *gin.Context) {
	var script Script
	if err := c.Bind(&script); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	key := c.Param("key")
	i, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	v, err := vm.Create(i, script.Code, script.License)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
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
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	vm.Delete(i)
}

func ScriptLogsHandler(c *gin.Context) {
	ws, err := websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set WebSocket upgrade:")
		return
	}
	defer ws.Close()

	vm.LogGlobal.Lock()
	vm.LogGlobal.Sockets = append(vm.LogGlobal.Sockets, ws)
	vm.LogGlobal.Unlock()

	done := make(chan bool)
	<-done
}

func PutConsts(c *gin.Context) {
	var consts map[string]interface{}
	if err := c.Bind(&consts); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	vm.SetConsts(consts)
}
