package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/server/controllers"
)

func ItemRoutes(ginApp *gin.Engine, opts *misc.Opts) {
	routeGroup := ginApp.Group("/item")

	routeGroup.GET("/:id", func(c *gin.Context) {
		controllers.GetItem(c, opts)
	})
}
