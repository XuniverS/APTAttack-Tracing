package model

import (
	"awesomeProject1/backend/utils"
	"strconv"
	"time"
)

type EventView struct {
	Timestamp   time.Time
	SourceIP    string
	DestIP      string
	EventType   string
	Severity    int
	Protocol    string
	PacketCount int
}

func GetEventViews() []EventView {
	var views []EventView

	// 直接使用utils.LogDB查询数据
	var attackLogs []utils.AttackLog
	utils.LogDB.Find(&attackLogs)

	var tcpLogs []utils.TcpLog
	utils.LogDB.Find(&tcpLogs)

	// 处理攻击日志
	for _, log := range attackLogs {
		views = append(views, EventView{
			Timestamp: log.LogTime,
			SourceIP:  log.SourceIP,
			DestIP:    log.DestIP,
			EventType: mapEventType(log.EventType),
			Severity:  log.Severity,
			Protocol:  mapProtocol(log.Protocol),
		})
	}

	// 处理TCP日志
	for _, log := range tcpLogs {
		views = append(views, EventView{
			Timestamp:   log.StartTime,
			SourceIP:    log.SrcIP,
			DestIP:      log.DestIP,
			EventType:   "TCP Connection",
			Protocol:    "TCP",
			PacketCount: log.PacketsSent,
		})
	}

	return views
}

func mapEventType(code int) string {
	switch code {
	case 1:
		return "端口扫描"
	case 2:
		return "暴力破解"
	case 3:
		return "C2通信"
	default:
		return "未知类型"
	}
}

func mapProtocol(code int) string {
	switch code {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return strconv.Itoa(code)
	}
}
