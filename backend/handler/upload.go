package handler

import (
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

	"awesomeProject1/backend/analyzePipe"
	"awesomeProject1/backend/utils"
)

const (
	attackLogMinFields = 3 // 根据实际字段数调整
	attackTimeColumn   = 1 // 日期字段位置
	attackTimeFormat   = "2006-01-02 15:04:05"
)

const (
	tcpLogMinFields   = 30
	tcpLogTimeCol     = 1
	tcpStartTimeCol   = 3
	tcpEndTimeCol     = 5
	tcpConnectionTime = 7
	tcpFlowStatus     = 9
	tcpDuration       = 10
	tcpServerIP       = 11
	tcpServerPort     = 12
	tcpClientIP       = 13
	tcpClientPort     = 14
	tcpTTLServer      = 15
	tcpTTLClient      = 16
	tcpProtocol       = 21
	tcpClientPLR      = 22 // 客户端丢包
	tcpServerPLR      = 25 // 服务器丢包
	tcpDownBPS        = 29 // 下行吞吐
	tcpUpBPS          = 30 // 上行吞吐
	tcpDownBytes      = 33
	tcpUpBytes        = 34
)

var (
	RawAttackData []utils.AttackLog
	RawTcpData    []utils.TcpLog
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
				RawAttackData = append(RawAttackData, logData)
			}
		case "tcp":
			if logData, ok := parseTcpLine(line); ok {
				if err := utils.LogDB.Create(&logData).Error; err != nil {
					log.Printf("TCP日志保存失败 行%d: %v", lineCount, err)
				}
				RawTcpData = append(RawTcpData, logData)
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

	// 解析时间字段
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

	establishedTimeStr := parts[tcpConnectionTime] + " " + parts[tcpConnectionTime+1]
	establishedTime, err := time.Parse(attackTimeFormat, establishedTimeStr)
	if err != nil {
		log.Printf("TCP连接时间解析失败: %v | 行内容: %s", err, line)
		return utils.TcpLog{}, false
	}

	// 解析其他字段
	return utils.TcpLog{
		LogTime:         logTime,
		StartTime:       startTime,
		EndTime:         endTime,
		EstablishedTime: establishedTime,
		FlowStatus:      safeAtoi(parts[tcpFlowStatus]),
		Duration:        safeAtof(parts[tcpDuration]),
		ServerIP:        parts[tcpServerIP],
		ServerPort:      safeAtoi(parts[tcpServerPort]),
		ClientIP:        parts[tcpClientIP],
		ClientPort:      safeAtoi(parts[tcpClientPort]),
		TTLServer:       safeAtoi(parts[tcpTTLServer]),
		TTLClient:       safeAtoi(parts[tcpTTLClient]),
		Protocol:        safeAtoi(parts[tcpProtocol]),
		ClientPLR:       safeAtof(parts[tcpClientPLR]),
		ServerPLR:       safeAtof(parts[tcpServerPLR]),
		DownBPS:         safeAtoi64(parts[tcpDownBPS]),
		UpBPS:           safeAtoi64(parts[tcpUpBPS]),
		DownBytes:       safeAtoi64(parts[tcpDownBytes]),
		UpBytes:         safeAtoi64(parts[tcpUpBytes]),

		PacketsSent:   safeAtoi(parts[31]),
		PacketReceive: safeAtoi(parts[32]),
		CustomStatus:  safeAtoi(parts[37]),
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
		return
	}

	if tcpFiles, ok := c.Request.MultipartForm.File["tcp"]; ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processFiles(tcpFiles, "tcp")
		}()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": "缺少TCP日志文件"})
		return
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
	if !analyzePipe.AnalyzePipeline() {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": errors})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
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

func safeAtoi64(s string) int64 {
	if s == "" {
		return 0
	}

	// 处理特殊字符（冒号、逗号等）
	cleanStr := strings.ReplaceAll(s, ":", "")       // 移除时间分隔符
	cleanStr = strings.ReplaceAll(cleanStr, ",", "") // 移除数字千分位分隔符

	// 使用 ParseInt 替代 Atoi 实现更精确的控制
	v, err := strconv.ParseInt(cleanStr, 10, 64) // 10进制，64位整数[2](@ref)
	if err != nil {
		if numError, ok := err.(*strconv.NumError); ok {
			// 详细错误分类处理
			switch numError.Err {
			case strconv.ErrRange:
				log.Printf("数值超出int64范围: %s (原始值 %s)", numError.Err, s)
			case strconv.ErrSyntax:
				log.Printf("非法数字格式: %s (原始值 %s)", numError.Err, s)
			}
		} else {
			log.Printf("未知转换错误: %s (原始值 %s)", err, s)
		}
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
