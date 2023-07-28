package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/metrics"
	"github.com/rs/zerolog/log"
)

func ServiceIpRoutes(app *gin.Engine) {
	var data map[string]map[string]string
	app.POST("/service_ips", func(c *gin.Context) {

		if err := c.ShouldBindJSON(&data); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		metrics.ServiceByIps = data["serviceByIp"]
		metrics.ServiceByClusterIps = data["serviceByClusterIp"]
		log.Info().
			Interface("serviceByIp", metrics.ServiceByIps).
			Interface("serviceByClusterIp", metrics.ServiceByClusterIps).
			Msg("setting service mapping")
		c.JSON(200, gin.H{"status": "ok"})
	})
}
