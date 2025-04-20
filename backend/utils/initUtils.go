package utils

import (
	"fmt"
	"log"
	"time"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	LogDB       *gorm.DB
	Neo4jDriver neo4j.Driver
)

func InitDatabase() {

	var err error

	LogDB, err = gorm.Open(mysql.New(mysql.Config{
		DSN:                       "UserName:yourPassword@tcp(127.0.0.1:3306)/log_analysis?parseTime=true",
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

	log.Printf("mysql初始化成功")
}

func InitNeo4j(uri, username, password string) error {
	driver, err := neo4j.NewDriver(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("Neo4j连接失败: %v", err)
	}
	Neo4jDriver = driver

	log.Printf("neo4j初始化成功")
	return nil
}
