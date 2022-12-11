package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func PcapRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/pcap")

	routeGroup.GET("/total-tcp-streams", controllers.GetTotalTcpStreams)
}
