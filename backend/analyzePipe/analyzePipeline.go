package analyzePipe

import (
	"awesomeProject1/backend/model"
	"awesomeProject1/backend/utils"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"log"
	"time"
)

func AnalyzePipeline() bool {
	analyzer := model.NewAnalyzer(utils.LogDB)
	go analyzer.RunAnalysis()

	correlator := model.NewTemporalCorrelator(utils.LogDB)
	phases, _ := correlator.DetectPhaseTransitions(time.Now().Add(-24*time.Hour), time.Now())

	builder := model.NewAttackGraphBuilder()
	inferer := model.NewBayesianInferer()

	// 构建攻击图
	log.Printf("开始构建攻击图，检测到%d个阶段", len(phases))
	for i := 1; i < len(phases); i++ {
		prev := phases[i-1]
		current := phases[i]
		log.Printf("添加阶段转移 %d/%d: %s(%s) -> %s(%s)",
			i, len(phases),
			prev.Phase, prev.SourceIP,
			current.Phase, current.SourceIP)
		builder.AddPhaseTransition(prev, current)
	}

	// 生成攻击路径
	inferer.GeneratePaths(phases)

	if err := builder.SaveToNeo4j(); err != nil {
		log.Printf("攻击图存储失败: %v", err)
		return false
	}

	// 保存攻击路径
	log.Printf("准备存储攻击图 (节点:%d 边:%d)", len(builder.Nodes), len(builder.Edges))
	if err := builder.SaveToNeo4j(); err != nil {
		log.Printf("攻击图存储失败: %v", err)
		return false
	}
	return true
}

func savePathsToNeo4j(paths []model.AttackPath) error {
	session := utils.Neo4jDriver.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	for _, path := range paths {
		_, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			// 创建路径节点
			_, err := tx.Run(
				`CREATE (p:AttackPath {confidence: $conf}) 
				WITH p
				UNWIND $phases AS phase
				MATCH (n:AttackPhase {phase: phase})
				MERGE (p)-[:CONTAINS]->(n)`,
				map[string]interface{}{
					"conf":   path.Confidence,
					"phases": path.Phases,
				})
			return nil, err
		})
		if err != nil {
			return err
		}
	}
	return nil
}
