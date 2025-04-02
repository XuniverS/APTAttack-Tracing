package model

import (
	"awesomeProject1/backend/utils"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"gorm.io/gorm"
	"log"
	"math"
	"sync"
	"time"
)

const (
	PhaseInitialAccess    = "InitialAccess"
	PhaseLateralMovement  = "LateralMovement"
	PhaseC2               = "CommandAndControl"
	PhaseDataExfiltration = "DataExfiltration"
	PhaseDefenseEvasion   = "DefenseEvasion"
	PhaseCredentialAccess = "CredentialAccess"
)

var eventTypeMapping = map[string]string{
	// 攻击者检测事件
	EventBruteForce:    PhaseInitialAccess,   // 高频暴力破解
	EventNewConnection: PhaseInitialAccess,   // 新IP连接
	EventPortScan:      PhaseLateralMovement, // 端口扫描
	EventProtoAnomaly:  PhaseLateralMovement, // 协议异常

	// 受害者检测事件
	EventReverseConnection:   PhaseC2,               // 反向连接
	EventDataTransfer:        PhaseDataExfiltration, // 数据渗出
	EventMaliciousConnection: PhaseInitialAccess,    // 恶意IP连接
	EventLongConnection:      PhaseC2,               // 长连接

	// 肉鸡检测事件
	EventZombieActivity:        PhaseC2, // 肉鸡新连接
	"ZOMBIE_ReverseConnection": PhaseC2, // 肉鸡反向连接
	"ZOMBIE_ACTIVITY_SPIKE":    PhaseC2, // 肉鸡活动激增
	"ZOMBIE_MALICIOUS_CONN":    PhaseC2, // 肉鸡恶意连接
}

type AttackNode struct {
	Phase       string    `neo4j:"phase"`
	Timestamp   time.Time `neo4j:"timestamp"`
	SourceIP    string    `neo4j:"sourceIP"`
	DestIP      string    `neo4j:"destIP"`
	RelatedLogs []uint
}

type AttackEdge struct {
	From       string
	To         string
	Confidence float64
	Count      int
}

type AttackPath struct {
	Phases     []string
	Confidence float64
}

type TemporalCorrelator struct {
	db            *gorm.DB
	timeWindow    time.Duration
	phaseSequence map[string][]string
}

func NewTemporalCorrelator(db *gorm.DB) *TemporalCorrelator {
	return &TemporalCorrelator{
		db:         db,
		timeWindow: 30 * time.Minute,
		phaseSequence: map[string][]string{
			PhaseInitialAccess:   {PhaseLateralMovement, PhaseC2},
			PhaseLateralMovement: {PhaseC2, PhaseDataExfiltration},
			PhaseC2:              {PhaseDataExfiltration},
		},
	}
}

func (tc *TemporalCorrelator) getPhaseThreshold(phase string) int {
	return 1
}

func (tc *TemporalCorrelator) filterValidSequence(phases []AttackNode) []AttackNode {
	validPhases := make([]AttackNode, 0)
	for i := range phases {
		if i == 0 {
			validPhases = append(validPhases, phases[i])
			continue
		}
		prevPhase := phases[i-1].Phase
		currentPhase := phases[i].Phase
		if utils.SliceContainsString(tc.phaseSequence[prevPhase], currentPhase) {
			validPhases = append(validPhases, phases[i])
		} else {
			log.Printf("[过滤] 无效阶段转移 %s->%s", prevPhase, currentPhase)
		}
	}
	return validPhases
}

func (tc *TemporalCorrelator) DetectPhaseTransitions(start, end time.Time) ([]AttackNode, error) {
	log.Printf("[阶段检测] 时间范围: %s ~ %s", start.Format("2006-01-02 15:04"), end.Format("2006-01-02 15:04"))

	var events []*utils.APTEvent
	if err := tc.db.Unscoped().
		Where("created_at BETWEEN ? AND ?", start.Format("2006-01-02 15:04"), end.Format("2006-01-02 15:04")).
		Order("created_at ASC").
		Find(&events).Error; err != nil {
		log.Printf("[错误] 数据库查询失败: %v", err)
		return nil, err
	}

	log.Printf("[阶段检测] 获取到%d个事件", len(events))
	if len(events) == 0 {
		return nil, nil
	}

	var phases []AttackNode
	currentWindow := make([]*utils.APTEvent, 0)
	lastPhaseTime := time.Time{}

	for _, event := range events {
		if event == nil {
			log.Println("[警告] 忽略空事件")
			continue
		}

		if !lastPhaseTime.IsZero() && event.StartTime.Sub(lastPhaseTime) > tc.timeWindow {
			if phase := tc.detectSinglePhase(currentWindow); phase != nil {
				phases = append(phases, *phase)
				currentWindow = currentWindow[:0]
			}
		}

		currentWindow = append(currentWindow, event)
		lastPhaseTime = event.StartTime
	}

	if phase := tc.detectSinglePhase(currentWindow); phase != nil {
		phases = append(phases, *phase)
	}

	log.Printf("[阶段检测] 生成%d个原始阶段", len(phases))
	return tc.filterValidSequence(phases), nil
}

func (tc *TemporalCorrelator) detectSinglePhase(events []*utils.APTEvent) *AttackNode {
	if len(events) == 0 {
		return nil
	}

	phaseCounter := make(map[string]int)
	var relatedLogs []uint
	ipSet := make(map[string]int)
	var matchedPhase string

	for _, event := range events {
		// 修改为使用统一的事件类型映射
		if phase, exists := eventTypeMapping[event.EventName]; exists {
			matchedPhase = phase
		}

		if matchedPhase == "" {
			log.Printf("[警告] 未识别事件类型: %s (ID:%d)", event.EventName, event.ID)
			continue
		}

		phaseCounter[matchedPhase]++
		relatedLogs = append(relatedLogs, uint(event.ID))
		ipSet[event.SourceIP]++
	}

	if len(phaseCounter) == 0 {
		return nil
	}

	maxPhase, maxCount := "", 0
	for phase, count := range phaseCounter {
		if count > maxCount {
			maxPhase = phase
			maxCount = count
		}
	}

	if maxCount < tc.getPhaseThreshold(maxPhase) {
		log.Printf("[过滤] 阶段%s计数不足: %d < %d", maxPhase, maxCount, tc.getPhaseThreshold(maxPhase))
		return nil
	}

	mainIP := ""
	maxIPCount := 0
	for ip, count := range ipSet {
		if count > maxIPCount {
			mainIP = ip
			maxIPCount = count
		}
	}

	return &AttackNode{
		Phase:       maxPhase,
		Timestamp:   events[0].StartTime,
		SourceIP:    mainIP,
		DestIP:      events[0].DestIP,
		RelatedLogs: relatedLogs,
	}
}

type AttackGraphBuilder struct {
	Nodes        map[string]AttackNode
	Edges        map[string]*AttackEdge
	transitionMu sync.RWMutex
	neo4jDriver  neo4j.Driver
}

func NewAttackGraphBuilder() *AttackGraphBuilder {
	return &AttackGraphBuilder{
		Nodes:       make(map[string]AttackNode),
		Edges:       make(map[string]*AttackEdge),
		neo4jDriver: utils.Neo4jDriver,
	}
}

func (bg *AttackGraphBuilder) AddPhaseTransition(from, to AttackNode) {
	if from.Phase == "" || to.Phase == "" {
		return
	}

	bg.transitionMu.Lock()
	defer bg.transitionMu.Unlock()

	bg.Nodes[from.Phase] = from
	bg.Nodes[to.Phase] = to

	key := from.Phase + "->" + to.Phase
	if edge, exists := bg.Edges[key]; exists {
		edge.Count++
		edge.Confidence = math.Min(edge.Confidence+0.1, 1.0)
	} else {
		bg.Edges[key] = &AttackEdge{
			From:       from.Phase,
			To:         to.Phase,
			Confidence: 0.3,
			Count:      1,
		}
	}

	log.Printf("[攻击图] 添加转移 %s -> %s (节点:%d 边:%d)",
		from.Phase, to.Phase, len(bg.Nodes), len(bg.Edges))
}

func (bg *AttackGraphBuilder) SaveToNeo4j() error {
	if bg.neo4jDriver == nil {
		return fmt.Errorf("Neo4j驱动未初始化")
	}

	session := bg.neo4jDriver.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	if _, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		_, err := tx.Run("MATCH (n:AttackPhase) DETACH DELETE n", nil)
		return nil, err
	}); err != nil {
		return fmt.Errorf("清空数据失败: %v", err)
	}

	nodeIDs := make(map[string]int64)
	for phase, node := range bg.Nodes {
		result, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return tx.Run(
				`MERGE (n:AttackPhase {phase: $phase}) 
				ON CREATE SET n.timestamp = $timestamp,
					n.sourceIP = $sourceIP,
					n.destIP = $destIP
				RETURN id(n)`,
				map[string]interface{}{
					"phase":     phase,
					"timestamp": node.Timestamp.Unix(),
					"sourceIP":  node.SourceIP,
					"destIP":    node.DestIP,
				})
		})
		if err != nil {
			return fmt.Errorf("创建节点失败: %v", err)
		}

		if records, ok := result.(neo4j.Result); ok && records.Next() {
			nodeIDs[phase] = records.Record().Values[0].(int64)
		}
	}

	for _, edge := range bg.Edges {
		_, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return tx.Run(
				`MATCH (a:AttackPhase {phase: $from}), (b:AttackPhase {phase: $to})
				MERGE (a)-[r:TRANSITION_TO]->(b)
				SET r.confidence = $conf,
					r.count = $count,
					r.lastUpdated = timestamp()`,
				map[string]interface{}{
					"from":  edge.From,
					"to":    edge.To,
					"conf":  edge.Confidence,
					"count": edge.Count,
				})
		})
		if err != nil {
			return fmt.Errorf("创建关系失败: %v", err)
		}
	}

	log.Printf("[Neo4j] 存储完成 (节点:%d 边:%d)", len(bg.Nodes), len(bg.Edges))
	return nil
}

type BayesianInferer struct {
	priorProb      map[string]float64
	transitionProb map[string]map[string]float64
}

func NewBayesianInferer() *BayesianInferer {
	return &BayesianInferer{
		priorProb: map[string]float64{
			PhaseInitialAccess:    0.2,
			PhaseLateralMovement:  0.3,
			PhaseC2:               0.4,
			PhaseDataExfiltration: 0.1,
		},
		transitionProb: map[string]map[string]float64{
			PhaseInitialAccess: {
				PhaseLateralMovement: 0.6,
				PhaseC2:              0.4,
			},
			PhaseLateralMovement: {
				PhaseC2:               0.5,
				PhaseDataExfiltration: 0.5,
			},
			PhaseC2: {
				PhaseDataExfiltration: 1.0,
			},
		},
	}
}

func (bi *BayesianInferer) GeneratePaths(phases []AttackNode) []AttackPath {
	paths := make([]AttackPath, 0)
	if len(phases) < 2 {
		return paths
	}

	for i := 1; i < len(phases); i++ {
		prev := phases[i-1].Phase
		current := phases[i].Phase
		prob := bi.priorProb[prev] * bi.transitionProb[prev][current]

		paths = append(paths, AttackPath{
			Phases:     []string{prev, current},
			Confidence: math.Round(prob*100) / 100,
		})
	}

	log.Printf("[推理] 生成%d条攻击路径", len(paths))
	return paths
}

func isInitialAccess(event *utils.APTEvent) bool {
	return event != nil && (event.EventName == EventBruteForce || event.EventName == EventNewConnection)
}

func isLateralMovement(event *utils.APTEvent) bool {
	return event != nil && (event.EventName == EventPortScan || event.EventName == EventProtoAnomaly)
}

func isC2(event *utils.APTEvent) bool {
	return event != nil && (event.EventName == EventC2Communication || event.EventName == EventReverseConnection)
}

func isDataExfiltration(event *utils.APTEvent) bool {
	return event != nil && (event.EventName == EventDataTransfer || event.BytesSent > 100*1024*1024)
}
