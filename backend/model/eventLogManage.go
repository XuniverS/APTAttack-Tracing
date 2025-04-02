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
	preAttackWindow      = 24 * time.Hour // 攻击前分析时间窗口
	postAttackWindow     = 48 * time.Hour // 攻击后分析时间窗口
	freqThreshold        = 10             // 连接频率阈值（次/小时）
	newIPThreshold       = 3              // 新IP数量阈值
	maliciousIPCheck     = true           // 是否启用恶意IP检查
	zombieWindow         = 72 * time.Hour // 肉鸡检测时间窗口
	zombieNewIPThreshold = 10             // 肉鸡新IP连接阈值
	zombieConnThreshold  = 100            // 肉鸡连接数阈值
)

// 新增事件类型常量定义
const (
	EventBruteForce          = "BruteForce"
	EventPortScan            = "PortScan"
	EventProtoAnomaly        = "ProtoAnomaly"
	EventC2Communication     = "C2Communication"
	EventDataTransfer        = "DataTransfer"
	EventNewConnection       = "NewConnection"
	EventReverseConnection   = "ReverseConnection"
	EventZombieActivity      = "ZombieActivity"
	EventMaliciousConnection = "MaliciousConnection"
	EventZombieSpike         = "ZombieSpike"
	EventLongConnection      = "LongConnection"
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
	attackMap  sync.Map // 攻击关系映射
}

type IPProfile struct {
	sync.RWMutex
	IP            string
	Connections   map[string]int
	TotalConnects int
	LastUpdated   time.Time
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

	zombieIPs := a.collectZombieIPs(flows)
	a.analyzeZombies(zombieIPs, attack)

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

// 检测规则1：受害者外联异常
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
			EventName:     EventReverseConnection,
			EventType:     PhaseC2,
			Description:   fmt.Sprintf("外联频率异常: 当前%d次/小时 (基线%d)", currentRate, baseline),
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则2：数据渗出检测
func (a *NAAnalyzer) detectDataExfiltration(flows []utils.TcpLog) DetectionResult {
	totalSent := 0
	for _, f := range flows {
		totalSent += int(f.UpBytes)
	}

	if totalSent > 100*1024*1024 {
		return DetectionResult{
			Triggered:     true,
			EventName:     EventDataTransfer,
			EventType:     PhaseDataExfiltration,
			Description:   fmt.Sprintf("异常数据外传: %.2f MB", float64(totalSent)/1024/1024),
			SeverityLevel: 5,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则3：恶意服务器连接
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
			EventName:     EventMaliciousConnection,
			EventType:     PhaseInitialAccess,
			Description:   fmt.Sprintf("连接已知恶意IP: %v", hits),
			SeverityLevel: 5, // 最高级别
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则4：C2通信检测
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
			EventName:     "LongConnection",
			EventType:     eventTypeMapping["LongConnection"],
			Description:   desc,
			SeverityLevel: 4,
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
				EventName:     EventBruteForce,
				EventType:     PhaseInitialAccess,
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
			EventName:     EventNewConnection,
			EventType:     PhaseInitialAccess,
			Description:   fmt.Sprintf("发现%d个新IP连接: %v", len(newIPs), newIPs),
			SeverityLevel: 2,
		}
	}
	return DetectionResult{Triggered: false}
}

// 检测规则3：端口扫描
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
			EventName:     EventPortScan,
			EventType:     PhaseLateralMovement,
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
			EventName:     EventProtoAnomaly,
			EventType:     PhaseLateralMovement,
			Description:   desc,
			SeverityLevel: 3,
		}
	}
	return DetectionResult{Triggered: false}
}

// 肉鸡检测
// 收集受害者连接过的IP（潜在肉鸡）
func (a *NAAnalyzer) collectZombieIPs(flows []utils.TcpLog) []string {
	ipSet := make(map[string]struct{})
	for _, f := range flows {
		ipSet[f.ServerIP] = struct{}{}
	}

	zombies := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		zombies = append(zombies, ip)
	}
	return zombies
}

// 肉鸡行为分析
func (a *NAAnalyzer) analyzeZombies(zombieIPs []string, attack utils.AttackLog) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 并发控制

	for _, zombieIP := range zombieIPs {
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			// 分析时间窗口：攻击发生后的时间段
			startTime := attack.LogTime
			endTime := startTime.Add(zombieWindow)

			var flows []utils.TcpLog
			a.db.Where("client_ip = ? AND start_time BETWEEN ? AND ?",
				ip,
				startTime,
				endTime,
			).Find(&flows)

			if len(flows) == 0 {
				return
			}

			// 执行肉鸡检测规则
			detections := []func([]utils.TcpLog, string) DetectionResult{
				a.detectZombieNewConnections,
				a.detectZombieReverseConn,
				a.detectZombieActivitySpike,
				a.detectZombieMaliciousConn,
			}

			var events []utils.APTEvent
			for _, detect := range detections {
				if result := detect(flows, attack.SourceIP); result.Triggered {
					events = append(events, utils.APTEvent{
						StartTime:     startTime,
						EndTime:       endTime,
						SourceIP:      ip,
						DestIP:        "",
						EventName:     result.EventName,
						EventType:     "ZOMBIE_" + result.EventType,
						SeverityLevel: result.SeverityLevel + 1, // 提高严重级别
						Description:   result.Description,
					})
				}
			}

			a.saveEvents(events)
		}(zombieIP)
	}
	wg.Wait()
}

// 肉鸡检测规则1：新IP连接异常
func (a *NAAnalyzer) detectZombieNewConnections(flows []utils.TcpLog, attackerIP string) DetectionResult {
	if len(flows) == 0 {
		return DetectionResult{Triggered: false}
	}
	historicalIPs := a.getHistoricalConnections(flows[0].ClientIP)
	var newIPs []string

	ipMap := make(map[string]struct{})
	for _, f := range flows {
		if _, exists := ipMap[f.ServerIP]; !exists {
			if !historicalIPs[f.ServerIP] {
				newIPs = append(newIPs, f.ServerIP)
			}
			ipMap[f.ServerIP] = struct{}{}
		}
	}

	if len(newIPs) >= zombieNewIPThreshold {
		return DetectionResult{
			Triggered:     true,
			EventName:     EventNewConnection,
			EventType:     PhaseInitialAccess,
			Description:   fmt.Sprintf("连接%d个新IP: %v", len(newIPs), newIPs),
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 肉鸡检测规则2：反向连接攻击者
func (a *NAAnalyzer) detectZombieReverseConn(flows []utils.TcpLog, attackerIP string) DetectionResult {

	var reverseConns int
	for _, f := range flows {
		if f.ServerIP == attackerIP {
			reverseConns++
		}
	}

	if reverseConns > 3 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "ZOMBIE_ReverseConnection",
			EventType:     PhaseC2,
			Description:   fmt.Sprintf("主动连接攻击者IP %s %d次", attackerIP, reverseConns),
			SeverityLevel: 5,
		}
	}
	return DetectionResult{Triggered: false}
}

// 肉鸡检测规则3：活动量激增
func (a *NAAnalyzer) detectZombieActivitySpike(flows []utils.TcpLog, _ string) DetectionResult {
	if len(flows) == 0 {
		return DetectionResult{Triggered: false}
	}
	baseline := a.getConnectionBaseline(flows[0].ClientIP)
	current := len(flows) / int(zombieWindow.Hours())

	if current > baseline*5 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "ZOMBIE_ACTIVITY_SPIKE",
			EventType:     PhaseC2,
			Description:   fmt.Sprintf("连接频率异常: %d次/小时 (基线%d)", current, baseline),
			SeverityLevel: 4,
		}
	}
	return DetectionResult{Triggered: false}
}

// 肉鸡检测规则4：恶意连接
func (a *NAAnalyzer) detectZombieMaliciousConn(flows []utils.TcpLog, _ string) DetectionResult {
	if !maliciousIPCheck {
		return DetectionResult{Triggered: false}
	}

	maliciousSet := make(map[string]struct{})
	for _, ip := range maliciousIPs {
		maliciousSet[ip] = struct{}{}
	}

	var hits int
	for _, f := range flows {
		if _, exists := maliciousSet[f.ServerIP]; exists {
			hits++
		}
	}

	if hits > 0 {
		return DetectionResult{
			Triggered:     true,
			EventName:     "ZOMBIE_MALICIOUS_CONN",
			EventType:     PhaseC2,
			Description:   fmt.Sprintf("连接%d次已知恶意IP", hits),
			SeverityLevel: 5,
		}
	}
	return DetectionResult{Triggered: false}
}

// 获取历史连接IP画像
func (a *NAAnalyzer) getHistoricalConnections(ip string) map[string]bool {
	profile, exists := a.ipProfiles.Load(ip)
	if !exists {
		return make(map[string]bool)
	}
	p, ok := profile.(*IPProfile)
	if !ok || p == nil {
		return make(map[string]bool)
	}
	connections := make(map[string]bool)
	for serverIP := range p.Connections {
		connections[serverIP] = true
	}
	return connections
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

func NewIPProfile(ip string) *IPProfile {
	return &IPProfile{
		IP:          ip,
		Connections: make(map[string]int),
	}
}

func (p *IPProfile) AddConnection(serverIP string) {
	p.Lock()
	defer p.Unlock()
	p.Connections[serverIP]++
	p.TotalConnects++
}

func (p *IPProfile) HasConnected(serverIP string) bool {
	p.RLock()
	defer p.RUnlock()
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
