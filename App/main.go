// Package main starts the Engine-AntiGinx scanner.
package main

import (
	"Engine-AntiGinx/App/GlobalHandler"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	_, f := os.LookupEnv("BACK_URL")
	errorHandler := GlobalHandler.InitializeErrorHandler(!f)
	errorHandler.RunSafe()
}
