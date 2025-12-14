package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	_ "github.com/go-sql-driver/mysql"
)

// DB 全局数据库连接
var DB *sql.DB

// Config 数据库配置
type Config struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DefaultConfig 返回默认数据库配置
func DefaultConfig() Config {
	return Config{
		DSN:             "root:password@tcp(127.0.0.1:3306)/webrtc_db?charset=utf8mb4&parseTime=True&loc=Local",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	}
}

// Init 初始化数据库连接
func Init(config Config) error {
	var err error

	// 打开数据库连接
	DB, err = sql.Open("mysql", config.DSN)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// 设置连接池参数
	DB.SetMaxOpenConns(config.MaxOpenConns)
	DB.SetMaxIdleConns(config.MaxIdleConns)
	DB.SetConnMaxLifetime(config.ConnMaxLifetime)

	// 测试连接
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	logger.Infof("Database connected successfully")
	return nil
}

// Close 关闭数据库连接
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// GetDB 获取数据库连接
func GetDB() *sql.DB {
	return DB
}
