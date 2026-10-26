// Package main starts the Engine-AntiGinx scanner.
package main

import (
	"Engine-AntiGinx/App/GlobalHandler"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	_, f := os.LookupEnv("PIPE_COMMUNICATION")
	errorHandler := GlobalHandler.InitializeErrorHandler(!f)
	errorHandler.RunSafe()
}
