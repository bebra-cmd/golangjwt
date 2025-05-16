package main

import (
	"authgolang/cmd/handlers"
	"authgolang/internal/crypto"
	"authgolang/internal/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

// buffer of generated tokens+bcrypt(tokens)
const BufferedSize = 1000

// queue length
const WorkerPoolSize = 10

func main() {
	server := gin.Default()
	buffered_refresh := make(chan crypto.TokenHash, BufferedSize)
	killChan := make(chan struct{})
	for i := 0; i < WorkerPoolSize; i++ {
		go crypto.GenerateRefreshToken(buffered_refresh, killChan)
	}
	server.POST("/auth", handlers.GetPair(buffered_refresh))
	server.POST("/refresh", handlers.RefreshPair(buffered_refresh))
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
	defer close(killChan)
	defer close(buffered_refresh)
}
