package routes

import (
	"awesomeProject1/backend/handler"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	uploadGroup := router.Group("/api/v1")
	{
		uploadGroup.POST("/upload", handler.UploadHandler)
		uploadGroup.POST("/inquire", handler.InquireHandler)
		uploadGroup.POST("/refresh", handler.RefreshHandler)
	}

	return router
}
