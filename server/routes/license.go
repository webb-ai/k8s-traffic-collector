package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func LicenseRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/license")

	routeGroup.POST("", controllers.SetLicense)
}
