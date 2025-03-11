package routes

import (
	"awesomeProject1/backend/handler"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	// 文件上传路由
	uploadGroup := router.Group("/api/v1")
	{
		uploadGroup.POST("/upload", handler.UploadHandler)
	}

	return router
}
