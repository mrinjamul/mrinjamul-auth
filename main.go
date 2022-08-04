package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mrinjamul/mrinjamul-auth/api/routes"
)

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
