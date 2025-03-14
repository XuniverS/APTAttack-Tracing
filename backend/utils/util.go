package utils

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
	ID        uint      `gorm:"primaryKey;autoIncrement"`                    // 主键，自动增长
	LogTime   time.Time `gorm:"column:log_time;type:datetime;not null"`      // 日志时间，DATETIME 类型，不为空
	EventType int       `gorm:"column:event_type;type:int;not null"`         // 事件类型，整数，不为空
	SourceIP  string    `gorm:"column:source_ip;type:varchar(255);not null"` // 源IP地址，VARCHAR 类型，不为空
	Protocol  int       `gorm:"column:protocol;type:int;not null"`           // 协议，整数，不为空
	Action    string    `gorm:"column:action;type:varchar(255);not null"`    // 行为，VARCHAR 类型，不为空
	DestIP    string    `gorm:"column:dest_ip;type:varchar(255);not null"`   // 目标IP地址，VARCHAR 类型，不为空
	Severity  int       `gorm:"column:severity;type:int;not null"`           // 严重性，整数，不为空
}

type TcpLog struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`                  // 主键，自动增长
	StartTime   time.Time `gorm:"column:start_time;type:datetime;not null"`  // 开始时间，DATETIME 类型，不为空
	EndTime     time.Time `gorm:"column:end_time;type:datetime;not null"`    // 结束时间，DATETIME 类型，不为空
	SrcIP       string    `gorm:"column:src_ip;type:varchar(255);not null"`  // 源IP地址，VARCHAR 类型，不为空
	SrcPort     int       `gorm:"column:src_port;type:int;not null"`         // 源端口，整数，不为空
	DestIP      string    `gorm:"column:dest_ip;type:varchar(255);not null"` // 目标IP地址，VARCHAR 类型，不为空
	DestPort    int       `gorm:"column:dest_port;type:int;not null"`        // 目标端口，整数，不为空
	PacketsSent int       `gorm:"column:packets_sent;type:int;not null"`     // 发送的数据包数，整数，不为空
	BytesSent   int       `gorm:"column:bytes_sent;type:int;not null"`       // 发送的字节数，整数，不为空
	Duration    float64   `gorm:"column:duration;type:float;not null"`       // 持续时间，浮动数，不为空
	StatusCode  int       `gorm:"column:status_code;type:int;not null"`      // 状态码，整数，不为空
}
