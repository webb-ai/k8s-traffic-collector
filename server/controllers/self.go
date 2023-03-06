package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/misc"
)

type Self struct {
	Host string `json:"host"`
	Node string `json:"node"`
}

func PostSelfHostNode(c *gin.Context) {
	var self Self
	if err := c.Bind(&self); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	misc.SetSelfHost(self.Host)
	misc.SetSelfNode(self.Node)
}
