package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func ScriptsRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/scripts")

	routeGroup.PUT("/:key", func(c *gin.Context) {
		controllers.PutScript(c)
	})
	routeGroup.DELETE("/:key", controllers.DeleteScript)

	routeGroup.GET("/logs", func(c *gin.Context) {
		controllers.ScriptLogsHandler(c)
	})
}
