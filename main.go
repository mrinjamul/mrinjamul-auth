package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mrinjamul/go-utils/tzinit"
	"github.com/mrinjamul/mrinjamul-auth/api/routes"
	"github.com/mrinjamul/mrinjamul-auth/config"
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

//go:embed templates/*
var webpages embed.FS

func main() {
	// Get the configuration
	cfg := config.GetConfig()
	port := ":" + cfg.Server.Port
	// Set the router as the default one shipped with Gin
	server := gin.Default()
	templ := template.Must(template.New("").ParseFS(webpages, "templates/layouts/*.html"))
	server.SetHTMLTemplate(templ)
	static, err := fs.Sub(webpages, "templates/static")
	if err != nil {
		panic(err)
	}
	// media, err := fs.Sub(webpages, "templates/media")
	// if err != nil {
	// 		panic(err)
	// }
	server.StaticFS("/static", http.FS(static))
	// server.StaticFS("/media", http.FS(media))

	// Initialize the routes
	routes.StartTime = startTime
	routes.InitRoutes(server)
	routes.BootTime = time.Since(startTime)

	// Start and run the server
	log.Fatal(server.Run(port))
}
