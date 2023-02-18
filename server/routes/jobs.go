package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/server/controllers"
)

func JobsRoutes(ginApp *gin.Engine) {
	routeGroup := ginApp.Group("/jobs")

	routeGroup.GET("/:tag", controllers.GetJob)
	routeGroup.DELETE("/:tag", controllers.DeleteJob)

	routeGroup.POST("/run/:tag", controllers.PostRunJob)
	routeGroup.POST("/run", controllers.PostRunAllJobs)

	routeGroup.GET("/scheduler/status", controllers.GetSchedulerStatus)
	routeGroup.POST("/scheduler/start", controllers.PostSchedulerStart)
	routeGroup.POST("/scheduler/stop", controllers.PostSchedulerStop)

	routeGroup.GET("", controllers.GetAllJobs)
	routeGroup.DELETE("", controllers.DeleteAllJobs)
}
