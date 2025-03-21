package analyzePipe

import (
	"awesomeProject1/backend/model"
	"awesomeProject1/backend/utils"
)

func AnalyzePipeline() bool {
	analyzer := model.NewAnalyzer(utils.LogDB)
	go analyzer.RunAnalysis()
	return true
}
