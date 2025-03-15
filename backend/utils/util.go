package utils

import (
	"sync"
	"time"
)

var (
	AttackFiles sync.Map
	TcpFiles    sync.Map
)

type AttackLog struct {
	ID        uint      `gorm:"primaryKey"`
	LogTime   time.Time `gorm:"column:log_time"`
	EventType int       `gorm:"column:event_type"`
	SourceIP  string    `gorm:"column:source_ip"`
	Protocol  int       `gorm:"column:protocol"`
	Action    string    `gorm:"column:action"`
	DestIP    string    `gorm:"column:dest_ip"`
	Severity  int       `gorm:"column:severity"`
}

type TcpLog struct {
	ID          uint      `gorm:"primaryKey"`
	StartTime   time.Time `gorm:"column:start_time"`
	EndTime     time.Time `gorm:"column:end_time"`
	SrcIP       string    `gorm:"column:src_ip"`
	SrcPort     int       `gorm:"column:src_port"`
	DestIP      string    `gorm:"column:dest_ip"`
	DestPort    int       `gorm:"column:dest_port"`
	PacketsSent int       `gorm:"column:packets_sent"`
	BytesSent   int       `gorm:"column:bytes_sent"`
	Duration    float64   `gorm:"column:duration"`
	StatusCode  int       `gorm:"column:status_code"`
}
