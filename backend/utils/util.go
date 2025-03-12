package model

import (
	"sync"
	"time"
)

type UploadedFile struct {
	FieldName string // 字段类型标识（type1/type2）
	FileName  string // 原始文件名
	FileSize  int64  // 文件大小
	// 可扩展其他元数据字段
}

var (
	AttackFiles sync.Map
	TcpFiles    sync.Map
)

type AttackLog struct {
	LogTime   time.Time
	EventType int
	SourceIP  string
	Protocol  int
	Action    string
	DestIP    string
	Severity  int
}

type TcpLog struct {
	StartTime   time.Time
	EndTime     time.Time
	SrcIP       string
	SrcPort     int
	DestIP      string
	DestPort    int
	PacketsSent int
	BytesSent   int
	Duration    float64
	StatusCode  int
}
