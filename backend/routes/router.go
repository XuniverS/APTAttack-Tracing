package routes

import (
	"awesomeProject1/backend/handler"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	apiGroup := router.Group("/api/v1")
	{
		apiGroup.POST("/upload", handler.UploadHandler)
		apiGroup.POST("/inquire", handler.InquireHandler)
		apiGroup.GET("/refresh", handler.RefreshHandler)
	}

	return router
}
