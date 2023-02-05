package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func ScriptsRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/scripts")

	routeGroup.PUT("/:key", controllers.PutScript)
	routeGroup.DELETE("/:key", controllers.DeleteScript)

	routeGroup.GET("/logs", controllers.ScriptLogsHandler)

	routeGroup.PUT("/consts", controllers.PutConsts)
}
