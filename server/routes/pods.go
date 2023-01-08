package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func PodsRoutes(ginApp *gin.Engine, procfs string) {
	routeGroup := ginApp.Group("/pods")

	routeGroup.POST("/set-targeted", func(c *gin.Context) {
		controllers.PostSetTargeted(c, procfs)
	})
}
