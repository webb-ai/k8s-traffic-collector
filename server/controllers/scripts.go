package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/vm"
)

type Script struct {
	Title string `json:"title"`
	Code  string `json:"code"`
}

func PutScript(c *gin.Context) {
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

	v, err := vm.Create(script.Code)
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
	vm.Delete(i)
}
