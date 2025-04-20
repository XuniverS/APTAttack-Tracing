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

type PageRequest struct {
	Page     int `form:"page"`     // 当前页码（从1开始）
	PageSize int `form:"pageSize"` // 每页数量（固定50）
}

type PaginatedResponse struct {
	CurrentPage int              `json:"currentPage"`
	PageSize    int              `json:"pageSize"`
	TotalPages  int              `json:"totalPages"`
	TotalCount  int64            `json:"totalCount"`
	Data        []utils.APTEvent `json:"data"`
}

func QuaryAPTEvents(c *gin.Context) {
	DB := utils.LogDB

	var req PageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid parameters"})
		return
	}

	// 设置默认值
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 50 // 默认每页50条
	}

	var events []utils.APTEvent
	var totalCount int64

	// 获取总数
	DB.Model(&utils.APTEvent{}).Count(&totalCount)

	// 执行分页查询
	err := DB.Model(&utils.APTEvent{}).
		Order("created_at DESC"). // 按创建时间倒序
		Limit(req.PageSize).
		Offset((req.Page - 1) * req.PageSize).
		Find(&events).Error

	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}

	// 计算总页数
	totalPages := int(totalCount) / req.PageSize
	if int(totalCount)%req.PageSize != 0 {
		totalPages++
	}

	c.JSON(200, PaginatedResponse{
		CurrentPage: req.Page,
		PageSize:    req.PageSize,
		TotalPages:  totalPages,
		TotalCount:  totalCount,
		Data:        events,
	})
}
