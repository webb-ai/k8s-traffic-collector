package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func PcapsRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/pcaps")

	routeGroup.GET("/total-tcp-streams", controllers.GetTotalTcpStreams)
	routeGroup.GET("/download/:id", controllers.GetDownloadPcap)
	routeGroup.POST("/merge", controllers.PostMerge)
	routeGroup.GET("/replay/:id", controllers.GetReplay)
	routeGroup.GET("/name-resolution-history", controllers.GetNameResolutionHistory)
}
