package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func SelfRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/self")

	routeGroup.POST("/set-host-node", controllers.PostSelfHostNode)
}
