package utils

import (
	"gorm.io/gorm"
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
	ID              uint      `gorm:"primaryKey"`
	LogTime         time.Time `gorm:"column:log_time"`         // SAVETIME
	StartTime       time.Time `gorm:"column:start_time"`       // BEGINTIME
	EndTime         time.Time `gorm:"column:end_time"`         // ENDTIME
	EstablishedTime time.Time `gorm:"column:established_time"` // ESTABLISHTIME（重命名更准确）
	FlowStatus      int       `gorm:"column:flow_status"`      // FLOWSTATUS（新增）
	Duration        float64   `gorm:"column:duration"`         // SECONDS
	ServerIP        string    `gorm:"column:server_ip"`        // SERVERIP（原DestIP）
	ServerPort      int       `gorm:"column:server_port"`      // SERVERPORT（原DestPort）
	ClientIP        string    `gorm:"column:client_ip"`        // CLIENTIP（原SrcIP）
	ClientPort      int       `gorm:"column:client_port"`      // CLIENTPORT（原SrcPort）
	TTLServer       int       `gorm:"column:ttl_server"`       // TTLSERVER（新增）
	TTLClient       int       `gorm:"column:ttl_client"`       // TTLCLIENT（新增）
	Protocol        int       `gorm:"column:protocol"`         // PROTOCOL（原AppProtocol）
	ClientPLR       float64   `gorm:"column:client_plr"`       // CLIENTPLR（新增）
	ServerPLR       float64   `gorm:"column:server_plr"`       // SERVERPLR（新增）
	DownBPS         int64     `gorm:"column:down_bps"`         // DOWNBPS（新增）
	UpBPS           int64     `gorm:"column:up_bps"`           // UPBPS（新增）
	DownBytes       int64     `gorm:"column:down_bytes"`       // DOWNBYTES（原BytesReceived）
	UpBytes         int64     `gorm:"column:up_bytes"`         // UPBYTES（原BytesSent）

	// 保留字段（根据实际需要）
	FragmentFlag  int `gorm:"column:fragment_flag"`
	StatusCode    int `gorm:"column:status_code"`
	PacketsSent   int `gorm:"column:packets_sent"`
	PacketReceive int `gorm:"column:packets_receive"`
	CustomStatus  int `gorm:"column:custom_status"`
}

// APT事件主模型
type APTEvent struct {
	gorm.Model
	StartTime     time.Time     `gorm:"index"`                  // 事件开始时间
	EndTime       time.Time     `gorm:"index"`                  // 事件结束时间
	SourceIP      string        `gorm:"type:varchar(45);index"` // 源IP
	DestIP        string        `gorm:"type:varchar(45);index"` // 目标IP
	EventName     string        `gorm:"type:varchar(100)"`      // 事件名称
	EventType     string        `gorm:"type:varchar(50);index"` // 事件类型
	SeverityLevel int           `gorm:"default:3"`              // 严重等级（1-5）
	Description   string        `gorm:"type:text"`              // 事件描述
	Metadata      EventMetadata `gorm:""`
}

// 元数据结构示例（根据检测规则动态生成）
type EventMetadata struct {
	Flags         int    `json:"flags"`          // 对应索引10标志位
	SrcPort       int    `json:"src_port"`       // 源端口（索引12）
	DestPort      int    `json:"dest_port"`      // 目标端口（索引14）
	BytesSent     int64  `json:"bytes_sent"`     // 发送字节数（索引26）
	BytesReceived int64  `json:"bytes_received"` // 接收字节数（索引27）
	StatusCode    int    `json:"status_code"`    // 状态码（索引21）
	Retransmits   int    `json:"retransmits"`    // 重传次数（索引33）
	Protocol      string `json:"protocol"`       // 协议类型（索引9/47）
}
