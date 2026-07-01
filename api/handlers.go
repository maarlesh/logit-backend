package api

import (
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() *gorm.DB {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file loaded: %v", err)
	}
	dsn := os.Getenv("DB_URL")
	pgxConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		log.Fatal("Failed to parse DB config:", err)
	}
	pgxConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	sqlDB := stdlib.OpenDB(*pgxConfig)
	DB, err = gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	if err := DB.AutoMigrate(&User{}, &Record{}, &Session{}); err != nil {
		log.Fatal("Failed to migrate schema:", err)
	}

	return DB
}

