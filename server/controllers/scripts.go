package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

type Script struct {
	Node  string `json:"node"`
	IP    string `json:"ip"`
	Title string `json:"title"`
	Code  string `json:"code"`
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

	v, err := vm.Create(i, script.Code, script.Node, script.IP)
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

func PutEnv(c *gin.Context) {
	var env map[string]interface{}
	if err := c.Bind(&env); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	vm.SetEnv(env)
}
