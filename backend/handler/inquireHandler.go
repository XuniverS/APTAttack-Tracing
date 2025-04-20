package handler

import (
	"awesomeProject1/backend/utils"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
)

func errorResponse(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"status": "error", "message": message})
}

func RefreshHandler(c *gin.Context) {
	// 获取分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset := (page - 1) * limit

	aptEvents, total, err := quaryAll(offset, limit)
	if err != nil {
		log.Printf("查询失败: %v", err)
		errorResponse(c, http.StatusInternalServerError, "数据获取失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"total":  total,
			"events": aptEvents,
		},
	})
}

func InquireHandler(c *gin.Context) {
	var queryParams struct {
		ID uint `json:"id" binding:"required"`
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

func quaryAll(offset, limit int) ([]utils.APTEvent, int64, error) {
	var aptEvents []utils.APTEvent
	var total int64
	DB := utils.LogDB

	// 获取总数
	DB.Model(&utils.APTEvent{}).Count(&total)

	// 分页查询
	result := DB.Order("created_at desc").Offset(offset).Limit(limit).Find(&aptEvents)
	if result.Error != nil {
		return nil, 0, result.Error
	}
	return aptEvents, total, nil
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
