package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/queue"
	"github.com/kubeshark/worker/target"
	v1 "k8s.io/api/core/v1"
)

func PostSetTargeted(c *gin.Context, procfs string, updateTargetsQueue *queue.Queue) {
	var pods []v1.Pod
	if err := c.Bind(&pods); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	go target.UpdatePods(pods, procfs, updateTargetsQueue)
}
