package handler

import (
	"awesomeProject1/backend/utils"
	"bufio"
	"fmt"
	"log"
	"mime/multipart"
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
		log.Printf("文件打开失败: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		switch fileType {
		case "attack":
			if logData, ok := parseAttackLine(line); ok {
				if err := utils.LogDB.Create(&logData).Error; err != nil {
					log.Printf("攻击日志保存失败 行%d: %v", lineCount, err)
				}
			}
		case "tcp":
			if logData, ok := parseTcpLine(line); ok {
				if err := utils.LogDB.Create(&logData).Error; err != nil {
					log.Printf("TCP日志保存失败 行%d: %v", lineCount, err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("文件读取错误: %v", err)
	}
}

func parseAttackLine(line string) (utils.AttackLog, bool) {
	parts := strings.Fields(line)
	if len(parts) < 9 { // 根据日志样本调整字段数量
		log.Printf("攻击日志字段不足: %s", line)
		return utils.AttackLog{}, false
	}

	// 示例攻击日志格式: 1 2019-07-20 05:38:00 1 209.147.138.11 1 fake_tcpflows 192.168.3.29 1
	timeStr := parts[1] + " " + parts[2]
	logTime, err := time.Parse("2006-01-02 15:04:05", timeStr)
	if err != nil {
		log.Printf("时间解析失败: %v | 行内容: %s", err, line)
		return utils.AttackLog{}, false
	}

	return utils.AttackLog{
		LogTime:   logTime,
		EventType: safeAtoi(parts[3]),
		SourceIP:  parts[4],
		Protocol:  safeAtoi(parts[5]),
		Action:    parts[6],
		DestIP:    parts[7],
		Severity:  safeAtoi(parts[8]),
	}, true
}

func parseTcpLine(line string) (utils.TcpLog, bool) {
	parts := strings.Fields(line)
	if len(parts) < 13 { // 根据TCP日志样本调整
		log.Printf("TCP日志字段不足: %s", line)
		return utils.TcpLog{}, false
	}

	// 示例TCP日志格式: 1 2019-07-16 05:05:00 2019-07-16 05:05:20 ...
	startTime, _ := time.Parse("2006-01-02 15:04:05", parts[1]+" "+parts[2])
	endTime, _ := time.Parse("2006-01-02 15:04:05", parts[3]+" "+parts[4])

	return utils.TcpLog{
		StartTime:   startTime,
		EndTime:     endTime,
		SrcIP:       parts[5],
		SrcPort:     safeAtoi(parts[6]),
		DestIP:      parts[7],
		DestPort:    safeAtoi(parts[8]),
		PacketsSent: safeAtoi(parts[9]),
		BytesSent:   safeAtoi(parts[10]),
		Duration:    safeAtof(parts[11]),
		StatusCode:  safeAtoi(parts[12]),
	}, true
}

func UploadHandler(c *gin.Context) {
	utils.AttackFiles = sync.Map{}
	utils.TcpFiles = sync.Map{}

	// 解析上传文件
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "表单解析失败"})
		return
	}

	var wg sync.WaitGroup
	errorChan := make(chan error, 2)

	// 处理文件上传的通用函数
	processFiles := func(files []*multipart.FileHeader, logType string) { // 修正类型
		defer func() {
			if r := recover(); r != nil {
				errorChan <- fmt.Errorf("处理异常: %v", r)
			}
		}()

		for _, fileHeader := range files {
			// 创建上传目录
			uploadDir := "uploads"
			if err := os.MkdirAll(uploadDir, 0755); err != nil {
				errorChan <- fmt.Errorf("创建目录失败: %v", err)
				return
			}

			// 保存文件
			filePath := filepath.Join(uploadDir, fileHeader.Filename)
			if err := c.SaveUploadedFile(fileHeader, filePath); err != nil {
				errorChan <- fmt.Errorf("文件保存失败: %v", err)
				return
			}

			// 处理日志文件
			ParseAndSaveLogFile(filePath, logType)
		}
	}

	// 处理攻击日志
	if attackFiles, ok := c.Request.MultipartForm.File["attack"]; ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processFiles(attackFiles, "attack")
		}()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "缺少攻击日志文件"})
	}

	// 处理TCP日志
	if tcpFiles, ok := c.Request.MultipartForm.File["tcp"]; ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processFiles(tcpFiles, "tcp")
		}()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "缺少TCP日志文件"})
	}

	// 错误收集
	go func() {
		wg.Wait()
		close(errorChan)
	}()

	// 处理错误
	var errors []string
	for err := range errorChan {
		errors = append(errors, err.Error())
	}
	if len(errors) > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": errors})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "文件处理完成"})
}

func safeAtoi(s string) int {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("整数转换失败: %s", s)
	}
	return v
}

func safeAtof(s string) float64 {
	if s == "" {
		return 0.0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		log.Printf("浮点数转换失败: %s", s)
	}
	return v
}
