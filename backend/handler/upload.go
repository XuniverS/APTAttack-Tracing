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

// 攻击日志格式示例：
// 1 2019-07-20 05:38:00 1 209.147.138.11 1 fake_tcpflows 192.168.3.29 1
const (
	attackLogMinFields = 3 // 根据实际字段数调整
	attackTimeColumn   = 1 // 日期字段位置
	attackTimeFormat   = "2006-01-02 15:04:05"
)

// TCP日志格式示例：
// 1 2019-07-16 05:05:00 2019-07-16 05:05:20 ...
const (
	tcpLogMinFields     = 10
	tcpLogTimeCol       = 1  // tcp日志记录时间
	tcpStartTimeCol     = 3  // 流开始时间
	tcpEndTimeCol       = 5  // 流结束时间
	tcpConnectionTime   = 7  // tcp连接建立时间
	tcpSimplePosition   = 10 // 标志位
	tcpSrcIPCol         = 11 // 源IP
	tcpSrcPortCol       = 12 // 源端口
	tcpDestIPCol        = 13 // 目标IP
	tcpDestPortCol      = 14 // 目标端口
	tcpFragmentFlag     = 17 // 分片标志
	tcpStatusCodeCol    = 21 // 连接状态码
	tcpDurationCol      = 22 // 持续时间
	tcpBytesSentCol     = 26 // 发送字节数
	tcpBytesReceveCol   = 27 // 接收字节数
	tcpPacketsSentCol   = 29 // 发送包数
	tcpCustomStatusCode = 45 // 自定义状态码
	tcpAppProtocol      = 47 // 应用层协议
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

// 解析攻击日志
func parseAttackLine(line string) (utils.AttackLog, bool) {
	parts := strings.Fields(line)
	if parts[0] == "" {
		return utils.AttackLog{}, false
	}
	if len(parts) < attackLogMinFields {
		log.Printf("攻击日志字段不足: %s", line)
		return utils.AttackLog{}, false
	}

	// 合并日期和时间字段
	timeStr := parts[attackTimeColumn] + " " + parts[attackTimeColumn+1]
	logTime, err := time.Parse(attackTimeFormat, timeStr)
	if err != nil {
		log.Printf("时间解析失败: %v | 行内容: %s", err, line)
		return utils.AttackLog{}, false
	}

	return utils.AttackLog{
		LogTime:   logTime,
		EventType: safeAtoi(parts[3]), // 事件类型
		SourceIP:  parts[4],           // 源IP
		Protocol:  safeAtoi(parts[5]), // 协议
		Action:    parts[6],           // 行为
		DestIP:    parts[7],           // 目标IP
		Severity:  safeAtoi(parts[8]), // 严重性
	}, true
}

// 解析TCP日志
func parseTcpLine(line string) (utils.TcpLog, bool) {
	parts := strings.Fields(line)
	if len(parts) < tcpLogMinFields {
		log.Printf("TCP日志字段不足: %s", line)
		return utils.TcpLog{}, false
	}

	logTimeStr := parts[tcpLogTimeCol] + " " + parts[tcpLogTimeCol+1]
	logTime, err := time.Parse(attackTimeFormat, logTimeStr)
	if err != nil {
		log.Printf("TCP日志记录时间解析失败: %v | 行内容: %s", err, line)
		return utils.TcpLog{}, false
	}

	startTimeStr := parts[tcpStartTimeCol] + " " + parts[tcpStartTimeCol+1]
	startTime, err := time.Parse(attackTimeFormat, startTimeStr)
	if err != nil {
		log.Printf("TCP日志开始时间解析失败: %v | 行内容: %s", err, line)
		return utils.TcpLog{}, false
	}

	endTimeStr := parts[tcpEndTimeCol] + " " + parts[tcpEndTimeCol+1]
	endTime, err := time.Parse(attackTimeFormat, endTimeStr)
	if err != nil {
		log.Printf("TCP日志结束时间解析失败: %v | 行内容: %s", err, line)
		return utils.TcpLog{}, false
	}

	tcpStartTimeStr := parts[tcpConnectionTime] + " " + parts[tcpConnectionTime+1]
	tcpConnectTime, err := time.Parse(attackTimeFormat, tcpStartTimeStr)
	if err != nil {
		log.Printf("TCP连接开始时间解析失败: %v | 行内容: %s", err, line)
		return utils.TcpLog{}, false
	}

	return utils.TcpLog{
		LogTime:        logTime,
		StartTime:      startTime,
		EndTime:        endTime,
		TcpConnectTime: tcpConnectTime,
		Flags:          safeAtoi(parts[tcpSimplePosition]),
		SrcIP:          parts[tcpSrcIPCol],
		SrcPort:        safeAtoi(parts[tcpSrcPortCol]),
		DestIP:         parts[tcpDestIPCol],
		DestPort:       safeAtoi(parts[tcpDestPortCol]),
		FragmentFlag:   safeAtoi(parts[tcpFragmentFlag]),
		StatusCode:     safeAtoi(parts[tcpStatusCodeCol]),
		Duration:       safeAtof(parts[tcpDurationCol]),
		BytesSent:      safeAtoi(parts[tcpBytesSentCol]),
		BytesReceived:  safeAtoi(parts[tcpBytesReceveCol]),
		PacketsSent:    safeAtoi(parts[tcpPacketsSentCol]),
		CustomStatus:   safeAtoi(parts[tcpCustomStatusCode]),
		AppProtocol:    parts[tcpAppProtocol], // 注意：协议名为字符串，无需转换
	}, true
}

func UploadHandler(c *gin.Context) {
	utils.AttackFiles = sync.Map{}
	utils.TcpFiles = sync.Map{}

	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "表单解析失败"})
		return
	}

	var wg sync.WaitGroup
	errorChan := make(chan error, 2)

	processFiles := func(files []*multipart.FileHeader, logType string) {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- fmt.Errorf("处理异常: %v", r)
			}
		}()

		for _, fileHeader := range files {
			uploadDir := "uploads"
			if err := os.MkdirAll(uploadDir, 0755); err != nil {
				errorChan <- fmt.Errorf("创建目录失败: %v", err)
				return
			}

			filePath := filepath.Join(uploadDir, fileHeader.Filename)
			if err := c.SaveUploadedFile(fileHeader, filePath); err != nil {
				errorChan <- fmt.Errorf("文件保存失败: %v", err)
				return
			}

			// 打印调试信息
			log.Printf("正在处理文件: %s", filePath)
			ParseAndSaveLogFile(filePath, logType)
		}
	}

	if attackFiles, ok := c.Request.MultipartForm.File["attack"]; ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processFiles(attackFiles, "attack")
		}()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "缺少攻击日志文件"})
	}

	if tcpFiles, ok := c.Request.MultipartForm.File["tcp"]; ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processFiles(tcpFiles, "tcp")
		}()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "缺少TCP日志文件"})
	}

	go func() {
		wg.Wait()
		close(errorChan)
	}()

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

// 增强类型转换函数
func safeAtoi(s string) int {
	if s == "" {
		return 0
	}

	// 去除可能存在的冒号（针对时间字段）
	cleanStr := strings.ReplaceAll(s, ":", "")

	v, err := strconv.Atoi(cleanStr)
	if err != nil {
		log.Printf("整数转换失败: %s (原始值)", s)
		return 0
	}
	return v
}

func safeAtof(s string) float64 {
	if s == "" {
		return 0.0
	}

	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		log.Printf("浮点数转换失败: %s (原始值)", s)
		return 0.0
	}
	return v
}
