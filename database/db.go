package database

import (
	"fmt"
	"log"

	"github.com/mrinjamul/mrinjamul-auth/config"
	"github.com/mrinjamul/mrinjamul-auth/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	// IsConnected returns the connection status
	IsConnected bool
	IsSQLite    bool
	DB          *gorm.DB
)

func GetDB() *gorm.DB {
	var err error
	cfg := config.GetConfig()
	switch cfg.Database.Type {
	case "postgres":
		// Connect to DB
		sslMode := "require"
		if cfg.Database.Host == "localhost" {
			sslMode = "disable"
		}
		dest := fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Asia/Kolkata",
			cfg.Database.Host, cfg.Database.Username, cfg.Database.Password, cfg.Database.Name,
			cfg.Database.Port, sslMode)
		DB, err = gorm.Open(postgres.Open(dest), &gorm.Config{})

		if err == nil {
			IsConnected = true
		} else {
			log.Println("failed to connect database")
		}
	case "sqlite":
		// Connect to DB
		DB, err = gorm.Open(sqlite.Open(cfg.Database.Name), &gorm.Config{})
		if err == nil {
			IsConnected = true
		} else {
			log.Println("failed to connect database")
		}
	}

	// if unable to connect to database, create sqlite database
	if !IsConnected {
		// Create sqlite connection
		DB, err = gorm.Open(sqlite.Open("sqlite.db"), &gorm.Config{})
		if err == nil {
			IsConnected = true
			IsSQLite = true
		} else {
			log.Println("failed to connect database")
		}
	}

	// Migrate the schema
	DB.AutoMigrate(&models.User{})
	return DB
}
