package utils

import (
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var LogDB *gorm.DB

func InitDatabase() {

	var err error

	LogDB, err = gorm.Open(mysql.New(mysql.Config{
		DSN:                       "root:C0137yx.@tcp(127.0.0.1:3306)/log_analysis?parseTime=true",
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
	sqlDB, err := LogDB.DB()
	sqlDB.SetConnMaxIdleTime(time.Minute * 5)
	sqlDB.SetConnMaxLifetime(time.Hour * 2)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(20)
}
