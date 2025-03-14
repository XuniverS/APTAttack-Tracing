package handler

import (
	"awesomeProject1/backend/utils"
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func ParseAndSaveLogFile(fileName string, fileType string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if fileType == "attack" {
			// 解析攻击日志
			logData := ParseAttackLog(line)
			// 保存到数据库
			if err := SaveAttackLogToDatabase(logData); err != nil {
				log.Println("Error saving attack log:", err)
			}
		} else if fileType == "tcp" {
			// 解析TCP日志
			logData := ParseTcpLog(line)
			// 保存到数据库
			if err := SaveTcpLogToDatabase(logData); err != nil {
				log.Println("Error saving TCP log:", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
	}
}

//TODO:这里的日志里面的日期还是解析不出来。

func ParseAttackLog(line string) utils.AttackLog {
	// 解析一行攻击日志
	parts := strings.Fields(line)
	if len(parts) < 7 {
		log.Println("Log line has insufficient data:", line)
		return utils.AttackLog{}
	}

	// 如果解析失败，使用当前时间作为默认值
	logTime, err := time.Parse("2006-01-02 15:04:05", parts[1])
	if err != nil {
		logTime = time.Now() // 如果解析失败，使用当前时间
	}

	return utils.AttackLog{
		LogTime:   logTime,
		EventType: parseInt(parts[2]), // 根据实际数据解析
		SourceIP:  parts[3],
		Protocol:  parseInt(parts[4]), // 根据实际数据解析
		Action:    parts[5],
		DestIP:    parts[6],
		Severity:  parseInt(parts[7]), // 根据实际数据解析
	}
}

func ParseTcpLog(line string) utils.TcpLog {
	// 解析一行TCP日志
	parts := strings.Fields(line)
	if len(parts) < 8 {
		log.Println("Log line has insufficient data:", line)
		return utils.TcpLog{}
	}

	// 如果解析失败，使用当前时间作为默认值
	startTime, err := time.Parse("2006-01-02 15:04:05", parts[1])
	if err != nil {
		startTime = time.Now() // 使用当前时间
	}
	endTime, err := time.Parse("2006-01-02 15:04:05", parts[2])
	if err != nil {
		endTime = time.Now() // 使用当前时间
	}

	return utils.TcpLog{
		StartTime:   startTime,
		EndTime:     endTime,
		SrcIP:       parts[3],
		SrcPort:     parseInt(parts[4]), // 根据实际数据解析
		DestIP:      parts[5],
		DestPort:    parseInt(parts[6]),   // 根据实际数据解析
		PacketsSent: parseInt(parts[7]),   // 根据实际数据解析
		BytesSent:   parseInt(parts[8]),   // 根据实际数据解析
		Duration:    parseFloat(parts[9]), // 根据实际数据解析
		StatusCode:  parseInt(parts[10]),  // 根据实际数据解析
	}
}

func SaveAttackLogToDatabase(logData utils.AttackLog) error {
	// 保存攻击日志到数据库
	if err := utils.LogDB.Create(&logData).Error; err != nil {
		return fmt.Errorf("failed to save attack log: %v", err)
	}
	return nil
}

func SaveTcpLogToDatabase(logData utils.TcpLog) error {
	// 保存TCP日志到数据库
	if err := utils.LogDB.Create(&logData).Error; err != nil {
		return fmt.Errorf("failed to save TCP log: %v", err)
	}
	return nil
}

func parseInt(value string) int {
	// 用来安全地解析整数值
	result, err := strconv.Atoi(value)
	if err != nil {
		return 0 // 如果解析失败，返回 0 或其他默认值
	}
	return result
}

func parseFloat(value string) float64 {
	// 用来安全地解析浮动值
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0.0 // 如果解析失败，返回 0.0 或其他默认值
	}
	return result
}

func UploadHandler(c *gin.Context) {
	// 清空之前的文件缓存
	utils.AttackFiles = sync.Map{}
	utils.TcpFiles = sync.Map{}

	// 解析表单文件
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "表单解析失败"})
		return
	}

	// 处理攻击日志文件
	if type1Files, ok := c.Request.MultipartForm.File["attack"]; ok {
		for _, fileHeader := range type1Files {
			// 文件保存路径
			filePath := filepath.Join("uploads", fileHeader.Filename)
			if err := c.SaveUploadedFile(fileHeader, filePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "文件保存失败"})
				return
			}
			// 解析并保存日志到数据库
			ParseAndSaveLogFile(filePath, "attack")
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "attack log may have some trouble"})
	}

	// 处理TCP日志文件
	if type2Files, ok := c.Request.MultipartForm.File["tcp"]; ok {
		for _, fileHeader := range type2Files {
			// 文件保存路径
			filePath := filepath.Join("uploads", fileHeader.Filename)
			if err := c.SaveUploadedFile(fileHeader, filePath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "文件保存失败"})
				return
			}
			// 解析并保存日志到数据库
			ParseAndSaveLogFile(filePath, "tcp")
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "tcp log may have some trouble"})
	}

	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}
