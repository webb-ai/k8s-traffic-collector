package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
	"github.com/kubeshark/worker/vm"
)

func ScriptsRoutes(ginApp *gin.Engine, logChannel chan *vm.Log) {
	routeGroup := ginApp.Group("/scripts")

	routeGroup.PUT("/:key", func(c *gin.Context) {
		controllers.PutScript(c, logChannel)
	})
	routeGroup.DELETE("/:key", controllers.DeleteScript)

	routeGroup.GET("/logs", func(c *gin.Context) {
		controllers.ScriptLogsHandler(c)
	})
}
