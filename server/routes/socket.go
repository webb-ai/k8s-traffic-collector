package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/server/controllers"
)

func WebSocketRoutes(app *gin.Engine, opts *misc.Opts) {
	app.GET("/ws", func(c *gin.Context) {
		controllers.WebsocketHandler(c, opts)
	})
}
