package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/target"
	v1 "k8s.io/api/core/v1"
)

func PostSetTargeted(c *gin.Context, procfs string) {
	var pods []v1.Pod
	if err := c.Bind(&pods); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	target.UpdatePods(pods, procfs)
}
