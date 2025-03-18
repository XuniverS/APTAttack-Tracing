package model

import (
	"awesomeProject1/backend/utils"
	"fmt"
	"gorm.io/gorm"
	"log"
	"net"
	"strings"
)

const (
	highPortThreshold  = 40000
	dataExfilThreshold = 50 * 1024 * 1024 // 50MB
)

type Detector struct {
	db           *gorm.DB
	threatIntel  map[string]bool // 内存型威胁情报库
	c2Domains    map[string]bool // C2域名特征库
	internalNets []*net.IPNet    // 内网地址段
}

func NewDetector(db *gorm.DB) *Detector {
	return &Detector{
		db:          db,
		threatIntel: loadThreatIntel(),
		c2Domains:   loadC2Domains(),
		internalNets: []*net.IPNet{
			mustParseCIDR("192.168.0.0/16"),
			mustParseCIDR("10.0.0.0/8"),
			mustParseCIDR("172.16.0.0/12"),
		},
	}
}

// 主检测入口
func (d *Detector) Analyze(logEntry utils.TcpLog) {
	events := make([]utils.APTEvent, 0, 5)

	// 多维度检测逻辑
	if meta, ok := d.detectC2Communication(logEntry); ok {
		events = append(events, d.buildEvent(EventC2Communication, meta, logEntry))
	}

	if meta, ok := d.detectDataExfiltration(logEntry); ok {
		events = append(events, d.buildEvent(EventDataExfiltration, meta, logEntry))
	}

	if meta, ok := d.detectLateralMovement(logEntry); ok {
		events = append(events, d.buildEvent(EventLateralMovement, meta, logEntry))
	}

	if meta, ok := d.detectCovertChannel(logEntry); ok {
		events = append(events, d.buildEvent(EventProtocolAbuse, meta, logEntry))
	}

	// 批量保存事件
	if len(events) > 0 {
		if err := d.db.Create(&events).Error; err != nil {
			log.Printf("事件保存失败: %v", err)
		}
	}
}

// C2通信检测（参考网页3[3](@ref)的C&C通道特征）
func (d *Detector) detectC2Communication(entry utils.TcpLog) (utils.EventMetadata, bool) {
	meta := utils.EventMetadata{
		DestPort:      entry.DestPort,
		StatusCode:    entry.StatusCode,
		BytesSent:     entry.BytesSent,
		BytesReceived: entry.BytesReceived,
	}

	// 规则1：非常用端口+长连接
	isHighPort := entry.DestPort >= highPortThreshold
	longDuration := entry.Duration > 300 // 5分钟

	// 规则2：心跳包特征
	isHeartbeat := entry.BytesSent <= 150 && entry.BytesReceived <= 150 &&
		entry.PacketsSent >= 10 && entry.Duration > 60

	// 规则3：威胁情报匹配
	isKnownC2 := d.threatIntel[entry.DestIP] || d.isDgaDomain(entry.AppProtocol)

	return meta, (isHighPort && longDuration) || isHeartbeat || isKnownC2
}

// 数据外泄检测
func (d *Detector) detectDataExfiltration(entry utils.TcpLog) (utils.EventMetadata, bool) {
	meta := utils.EventMetadata{
		BytesSent:     entry.BytesSent,
		BytesReceived: entry.BytesReceived,
		Protocol:      entry.AppProtocol,
	}

	// 规则1：单向大流量
	isUniDirection := entry.BytesSent > dataExfilThreshold &&
		entry.BytesReceived < entry.BytesSent/100

	// 规则2：异常时间传输
	offHours := entry.LogTime.Hour() >= 22 || entry.LogTime.Hour() <= 6

	return meta, isUniDirection && offHours
}

// 横向移动检测
func (d *Detector) detectLateralMovement(entry utils.TcpLog) (utils.EventMetadata, bool) {
	meta := utils.EventMetadata{
		SrcPort:  entry.SrcPort,
		DestPort: entry.DestPort,
		Protocol: entry.AppProtocol,
	}

	// 规则1：内网扫描模式
	isInternal := d.isInternalIP(entry.SrcIP) && d.isInternalIP(entry.DestIP)
	isScanning := entry.PacketsSent > 1000 && entry.Duration < 10

	// 规则2：非常用协议
	isRareProtocol := strings.ToUpper(entry.AppProtocol) == "RDP" ||
		strings.ToUpper(entry.AppProtocol) == "SMB"

	return meta, isInternal && (isScanning || isRareProtocol)
}

// 隐蔽通道检测
func (d *Detector) detectCovertChannel(entry utils.TcpLog) (utils.EventMetadata, bool) {
	meta := utils.EventMetadata{
		Protocol:  entry.AppProtocol,
		BytesSent: entry.BytesSent,
		DestPort:  entry.DestPort,
	}

	// 规则1：TLS异常
	isTls := entry.DestPort == 443 || entry.DestPort == 8443
	isMalformedTLS := entry.BytesSent > 0 && entry.BytesReceived == 0

	// 规则2：DNS隐蔽隧道
	isDnsTunnel := entry.DestPort == 53 &&
		entry.BytesSent > 512 &&
		strings.Contains(entry.AppProtocol, "DNS")

	return meta, isMalformedTLS || isDnsTunnel
}

// 构建事件实体
func (d *Detector) buildEvent(eventType string, meta utils.EventMetadata, log utils.TcpLog) utils.APTEvent {
	return utils.APTEvent{
		StartTime:     log.StartTime,
		EndTime:       log.EndTime,
		SourceIP:      log.SrcIP,
		DestIP:        log.DestIP,
		EventType:     eventType,
		SeverityLevel: d.calculateSeverity(eventType, meta),
		Description:   generateDescription(eventType, meta),
		Metadata:      meta,
	}
}

// 辅助方法
func (d *Detector) isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	for _, net := range d.internalNets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *Detector) isDgaDomain(domain string) bool {
	// 实现DGA检测逻辑
	return strings.Contains(domain, ".tk") ||
		strings.Contains(domain, ".xyz") ||
		len(domain) > 30
}

func generateDescription(eventType string, meta utils.EventMetadata) string {
	switch eventType {
	case EventC2Communication:
		return fmt.Sprintf("检测到C2通信：目标端口%d 流量模式%s",
			meta.DestPort, formatTrafficPattern(meta))
	case EventDataExfiltration:
		return fmt.Sprintf("异常数据外传：发送%s 接收%s",
			formatBytes(meta.BytesSent), formatBytes(meta.BytesReceived))
		// 其他事件类型描述...
	}
	return ""
}

// 威胁情报加载示例
func loadThreatIntel() map[string]bool {
	return map[string]bool{
		"198.143.164.251": true,
		"45.76.188.129":   true,
	}
}
