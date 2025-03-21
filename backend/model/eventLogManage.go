package model

import (
	"awesomeProject1/backend/utils"
	"fmt"
	"gorm.io/gorm"
	"log"
	"sync"
	"time"
)

const (
	preAttackWindow  = 24 * time.Hour // 攻击前分析时间窗口
	postAttackWindow = 48 * time.Hour // 攻击后分析时间窗口
	freqThreshold    = 50             // 连接频率阈值（次/小时）
	newIPThreshold   = 5              // 新IP数量阈值
	maliciousIPCheck = true           // 是否启用恶意IP检查
)

type DetectionResult struct {
	Triggered     bool
	EventName     string
	EventType     string
	Description   string
	SeverityLevel int
}

var (
	maliciousIPs = []string{} // 恶意服务器ip
)

type NAAnalyzer struct {
	db         *gorm.DB
	ipProfiles sync.Map // IP行为画像缓存
}

func NewAnalyzer(db *gorm.DB) *NAAnalyzer {
	return &NAAnalyzer{
		db: db,
	}
}

// 主分析入口
func (a *NAAnalyzer) RunAnalysis() {
	var attacks []utils.AttackLog
	if err := a.db.Find(&attacks).Error; err != nil {
		log.Printf("攻击日志查询失败: %v", err)
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 并发控制

	for _, attack := range attacks {
		wg.Add(1)
		sem <- struct{}{}

		go func(aLog utils.AttackLog) {
			defer func() {
				<-sem
				wg.Done()
			}()

			// 分析攻击者行为
			a.analyzeAttacker(aLog)

			// 分析受害者行为
			a.analyzeVictim(aLog)
		}(attack)
	}

	wg.Wait()
}

// 攻击者行为分析
func (a *NAAnalyzer) analyzeAttacker(attack utils.AttackLog) {
	timeWindow := preAttackWindow
	startTime := attack.LogTime.Add(-timeWindow)
	endTime := attack.LogTime

	var flows []utils.TcpLog
	a.db.Where("client_ip = ? AND start_time BETWEEN ? AND ?",
		attack.SourceIP,
		startTime,
		endTime,
	).Find(&flows)

	// 更新检测规则集合
	detections := []func([]utils.TcpLog) DetectionResult{
		a.detectConnectionFrequency, // 高频连接检测
		a.detectNewIPConnections,    // 新IP连接检测
		a.detectPortScanPattern,     // 端口扫描检测
		a.detectProtocolAnomalies,   // 新增协议异常检测
	}

	var events []utils.APTEvent
	for _, detect := range detections {
		if result := detect(flows); result.Triggered {
			events = append(events, utils.APTEvent{
				StartTime:     startTime,
				EndTime:       endTime,
				SourceIP:      attack.SourceIP,
				DestIP:        attack.DestIP,
				EventName:     result.EventName,
				EventType:     result.EventType,
				SeverityLevel: result.SeverityLevel,
				Description:   result.Description,
			})
		}
	}

	a.saveEvents(events)
}

// 受害者行为分析
func (a *NAAnalyzer) analyzeVictim(attack utils.AttackLog) {
	startTime := attack.LogTime
	endTime := attack.LogTime.Add(postAttackWindow)

	var flows []utils.TcpLog
	a.db.Where("client_ip = ? AND start_time BETWEEN ? AND ?",
		attack.DestIP,
		startTime,
		endTime,
	).Find(&flows)

	// 更新检测规则集合
	detections := []func([]utils.TcpLog) DetectionResult{
		a.detectVictimOutbound,       // 外联异常检测
		a.detectDataExfiltration,     // 数据渗出检测
		a.detectMaliciousConnections, // 恶意连接检测
		a.detectC2Communication,      // 新增C2通信检测
	}

	var events []utils.APTEvent
	for _, detect := range detections {
		if result := detect(flows); result.Triggered {
			events = append(events, utils.APTEvent{
				StartTime:     startTime,
				EndTime:       endTime,
				SourceIP:      attack.DestIP,
				DestIP:        "",
				EventName:     result.EventName,
				EventType:     result.EventType,
				SeverityLevel: result.SeverityLevel,
				Description:   result.Description,
			})
		}
	}

	a.saveEvents(events)
}

// 检测规则4：受害者外联异常
func (a *NAAnalyzer) detectVictimOutbound(flows []utils.TcpLog) DetectionResult {
	if len(flows) == 0 {
		return DetectionResult{Triggered: false}
	}

	clientIP := flows[0].ClientIP
	baseline := a.getConnectionBaseline(clientIP)
	currentRate := len(flows) / int(postAttackWindow.Hours())

	if currentRate > baseline*3 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "受害主机外联激增",
			EventType:     "POST_OUTBOUND_SPIKE",
			Description:   fmt.Sprintf("外联频率异常: 当前%d次/小时 (基线%d)", currentRate, baseline),
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则5：数据渗出检测
func (a *NAAnalyzer) detectDataExfiltration(flows []utils.TcpLog) DetectionResult {
	totalSent := 0
	for _, f := range flows {
		totalSent += int(f.UpBytes)
	}

	if totalSent > 100*1024*1024 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "可疑数据渗出",
			EventType:     "POST_DATA_EXFIL",
			Description:   fmt.Sprintf("异常数据外传: %.2f MB", float64(totalSent)/1024/1024),
			SeverityLevel: 5,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则6：恶意服务器连接
func (a *NAAnalyzer) detectMaliciousConnections(flows []utils.TcpLog) DetectionResult {
	if !maliciousIPCheck {
		return DetectionResult{Triggered: false}
	}

	maliciousSet := make(map[string]struct{})
	for _, ip := range maliciousIPs {
		maliciousSet[ip] = struct{}{}
	}

	var hits []string
	for _, f := range flows {
		if _, exists := maliciousSet[f.ServerIP]; exists {
			hits = append(hits, f.ServerIP)
		}
	}

	if len(hits) > 0 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "恶意服务器通信",
			EventType:     "POST_MALICIOUS_CONN",
			Description:   fmt.Sprintf("连接已知恶意IP: %v", hits),
			SeverityLevel: 5, // 最高级别
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则1：高频连接
func (a *NAAnalyzer) detectConnectionFrequency(flows []utils.TcpLog) DetectionResult {
	hourlyConn := make(map[int]int)
	for _, f := range flows {
		hour := f.StartTime.Hour()
		hourlyConn[hour]++
	}

	for h, cnt := range hourlyConn {
		if cnt > freqThreshold {
			return DetectionResult{
				Triggered:     true,
				EventName:     "高频连接异常",
				EventType:     "PRE_HIGH_FREQ",
				Description:   fmt.Sprintf("异常连接频率: %d次/小时 (时段%d:00)", cnt, h),
				SeverityLevel: 3,
			}
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则2：新IP连接
func (a *NAAnalyzer) detectNewIPConnections(flows []utils.TcpLog) DetectionResult {
	ipMap := make(map[string]struct{})
	var newIPs []string

	for _, f := range flows {
		if _, exists := ipMap[f.ServerIP]; !exists {
			if !a.checkIPHistorical(f.ClientIP, f.ServerIP) {
				newIPs = append(newIPs, f.ServerIP)
			}
			ipMap[f.ServerIP] = struct{}{}
		}
	}

	if len(newIPs) >= newIPThreshold {
		return DetectionResult{
			Triggered:     true,
			EventName:     "新资产连接",
			EventType:     "PRE_NEW_ASSET",
			Description:   fmt.Sprintf("发现%d个新IP连接: %v", len(newIPs), newIPs),
			SeverityLevel: 2,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则3：端口扫描（修改后）
func (a *NAAnalyzer) detectPortScanPattern(flows []utils.TcpLog) DetectionResult {
	portCounter := make(map[int]int)
	for _, f := range flows {
		portCounter[f.ServerPort]++
	}

	var suspiciousPorts []int
	for port, cnt := range portCounter {
		if cnt > 3 {
			suspiciousPorts = append(suspiciousPorts, port)
		}
	}

	if len(suspiciousPorts) > 5 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "端口扫描行为",
			EventType:     "PRE_PORT_SCAN",
			Description:   fmt.Sprintf("疑似端口扫描，涉及%d个端口", len(suspiciousPorts)),
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则4：协议异常检测
func (a *NAAnalyzer) detectProtocolAnomalies(flows []utils.TcpLog) DetectionResult {
	validProtocols := map[int]struct{}{
		0: {}, // HTTP
		1: {}, // 交互式（游戏）
		2: {}, // 媒体
	}

	anomalyProtocols := make(map[int]int)
	for _, f := range flows {
		if _, ok := validProtocols[f.Protocol]; !ok {
			anomalyProtocols[f.Protocol]++
		}
	}

	if len(anomalyProtocols) > 0 {
		desc := "发现非常用业务协议: "
		for proto, cnt := range anomalyProtocols {
			desc += fmt.Sprintf("[%d]%d次 ", proto, cnt)
		}
		return DetectionResult{
			Triggered:     true,
			EventName:     "非常规协议通信",
			EventType:     "PRE_PROTO_ANOMALY",
			Description:   desc,
			SeverityLevel: 3,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则5：C2通信检测
func (a *NAAnalyzer) detectC2Communication(flows []utils.TcpLog) DetectionResult {
	const c2Threshold = 60 * 60 // 1小时持续通信
	var suspects []utils.TcpLog

	for _, f := range flows {
		if f.Duration > c2Threshold {
			suspects = append(suspects, f)
		}
	}

	if len(suspects) > 0 {
		desc := "发现长连接: "
		for _, s := range suspects {
			desc += fmt.Sprintf("%s:%d (%.1f小时) ", s.ServerIP, s.ServerPort, float64(s.Duration)/3600)
		}
		return DetectionResult{
			Triggered:     true,
			EventName:     "持久化连接",
			EventType:     "POST_C2_COMM",
			Description:   desc,
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 获取IP历史连接画像
func (a *NAAnalyzer) checkIPHistorical(clientIP, serverIP string) bool {
	if profile, exists := a.ipProfiles.Load(clientIP); exists {
		return profile.(*IPProfile).HasConnected(serverIP)
	}

	// 首次查询建立画像
	var history []utils.TcpLog
	a.db.Where("client_ip = ? AND start_time < ?",
		clientIP,
		time.Now().Add(-24*time.Hour),
	).Find(&history)

	profile := NewIPProfile(clientIP)
	for _, f := range history {
		profile.AddConnection(f.ServerIP)
	}
	a.ipProfiles.Store(clientIP, profile)

	return profile.HasConnected(serverIP)
}

// 获取连接频率基线
func (a *NAAnalyzer) getConnectionBaseline(ip string) int {
	if profile, exists := a.ipProfiles.Load(ip); exists {
		return profile.(*IPProfile).AverageConnections()
	}
	return 10 // 默认基线值
}

func (a *NAAnalyzer) saveEvents(events []utils.APTEvent) {
	if len(events) == 0 {
		return
	}

	tx := a.db.Begin()
	for _, e := range events {
		if err := tx.Create(&e).Error; err != nil {
			tx.Rollback()
			log.Printf("事件保存失败: %v", err)
			return
		}
	}
	tx.Commit()
}

// IP行为画像结构
type IPProfile struct {
	IP            string
	Connections   map[string]int // IP连接次数
	TotalConnects int
	LastUpdated   time.Time
}

func NewIPProfile(ip string) *IPProfile {
	return &IPProfile{
		IP:          ip,
		Connections: make(map[string]int),
	}
}

func (p *IPProfile) AddConnection(serverIP string) {
	p.Connections[serverIP]++
	p.TotalConnects++
}

func (p *IPProfile) HasConnected(serverIP string) bool {
	_, exists := p.Connections[serverIP]
	return exists
}

func (p *IPProfile) AverageConnections() int {
	days := time.Since(p.LastUpdated).Hours() / 24
	if days < 1 {
		days = 1
	}
	return p.TotalConnects / int(days)
}
