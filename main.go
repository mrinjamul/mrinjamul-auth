package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mrinjamul/mrinjamul-auth/api/routes"
)

// @title mrinjamul-auth API
// @version 1.0
// @description This is a authentication server for user management.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email mrinjamul@gmail.com
// @license.name MIT License
// @license.url https://github.com/mrinjamul/mrinjamul-auth/blob/main/LICENSE
// @BasePath /
// @schemes http https
// @securitydefinitions.apikey	APIKeyAuth
// @in header
// @name Authorization

var (
	startTime time.Time = time.Now()
)

func main() {
	// Get port from env
	port := ":3000"
	_, present := os.LookupEnv("PORT")
	if present {
		port = ":" + os.Getenv("PORT")

	}
	// Set the router as the default one shipped with Gin
	server := gin.Default()
	// Initialize the routes
	routes.StartTime = startTime
	routes.InitRoutes(server)
	routes.BootTime = time.Since(startTime)

	// Start and run the server
	log.Fatal(server.Run(port))
}
