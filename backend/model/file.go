package model

import "sync"

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
