package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/vm"
)

type postSetLicenseRequest struct {
	License bool `json:"license"`
}

func SetLicense(c *gin.Context) {
	var req postSetLicenseRequest
	if err := c.Bind(&req); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	vm.SetLicense(req.License)
}
