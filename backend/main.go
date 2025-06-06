package main

import (
	"awesomeProject1/backend/routes"
	"awesomeProject1/backend/utils"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
	"path/filepath"
	"runtime"
)

func getFrontendPath() string {
	_, currentFile, _, _ := runtime.Caller(0)          // 获取当前文件路径
	backendDir := filepath.Dir(currentFile)            // backend目录
	return filepath.Join(backendDir, "..", "frontend") // 上溯到父目录再进frontend
}

func init() {
	utils.InitDatabase()
	if err := utils.InitNeo4j(
		"bolt://localhost:7687",
		"neo4j",
		"yourPassword"); err != nil {
		log.Fatal(err)
	}
}

func main() {
	router := routes.SetupRouter()
	frontendPath := getFrontendPath()

	// CORS配置
	router.Use(cors.Default())

	// 静态文件服务
	router.Static("/static", frontendPath)

	// 根路径路由
	router.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(frontendPath, "index.html"))
	})

	// API路由（来自routes包）
	router.Run(":8080")
}
