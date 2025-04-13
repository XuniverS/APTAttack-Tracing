package handler

import (
	"awesomeProject1/backend/utils"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func errorResponse(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"status": "error", "message": message})
}

func RefreshHandler(c *gin.Context) {
	aptEvents, err := quaryAll()
	if err != nil {
		log.Printf("查询失败: %v", err)
		errorResponse(c, http.StatusInternalServerError, "数据获取失败")
		return
	}

	c.JSON(http.StatusOK, aptEvents)
}

func InquireHandler(c *gin.Context) {
	var queryParams struct {
		ID uint `json:"id" binding:"required"` // 要求必须包含ID
	}

	if err := c.ShouldBindJSON(&queryParams); err != nil {
		log.Printf("参数绑定错误: %v", err)
		errorResponse(c, http.StatusBadRequest, "无效请求参数")
		return
	}

	aptEvent, err := quaryAptEventByID(queryParams.ID)
	if err != nil {
		log.Printf("查询失败: %v", err)
		errorResponse(c, http.StatusNotFound, "未找到相关记录")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   aptEvent,
	})
}

func quaryAll() ([]utils.APTEvent, error) {
	var aptEvents []utils.APTEvent
	DB := utils.LogDB

	result := DB.Order("created_at desc").Limit(50).Find(&aptEvents) // 查询最新50条记录
	if result.Error != nil {
		return nil, result.Error
	}
	return aptEvents, nil
}

func quaryAptEventByID(id uint) (utils.APTEvent, error) {
	var aptEvent utils.APTEvent
	DB := utils.LogDB

	result := DB.First(&aptEvent, id)
	if result.Error != nil {
		return utils.APTEvent{}, result.Error
	}
	return aptEvent, nil
}
