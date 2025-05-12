package main

import (
	"authgolang/cmd/handlers"
	"authgolang/internal/crypto"
	"authgolang/internal/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	server := gin.Default()
	//rewrite it to worker pool
	buffered_refresh := make(chan crypto.TokenHash, 1000)
	go crypto.GenerateRefreshToken(buffered_refresh)
	server.POST("/auth", handlers.GetPair(buffered_refresh))
	server.POST("/refresh", handlers.RefreshPair)
	sql.Init()
	var logPath string
	if gin.IsDebugging() {
		logPath = "../../logs/app.log"

	} else {
		logPath = os.Getenv("LOG_PATH")
	}

	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		println(err.Error())
	}
	log.SetOutput(logFile)
	server.Run(":" + os.Getenv("APP_PORT"))
	defer sql.Global_db.Close()
	//add defer to close worker pool
}
