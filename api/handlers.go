package api

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() *gorm.DB {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
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
	if err := DB.AutoMigrate(&User{}); err != nil {
		log.Fatal("Failed to migrate schema:", err)
	}
	
	return DB
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func CreateUser(db *gorm.DB, c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		ResponseJSON(c, http.StatusBadRequest, "Invalid input", nil)
		return
	}
	if err := db.Create(&user).Error; err != nil {
		ResponseJSON(c, http.StatusInternalServerError, "Failed to create user", err)
		return
	}
	ResponseJSON(c, http.StatusCreated, "User created successfully", UserResponse{
		ID:    user.ID.String(),
		Email: user.Email,
	})
}
