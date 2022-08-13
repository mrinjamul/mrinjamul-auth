package routes

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mrinjamul/mrinjamul-auth/api/services"
	docs "github.com/mrinjamul/mrinjamul-auth/docs"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title mrinjamul-auth API
// @version 2.0
// @description This is a authentication server for user management.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email mrinjamul@gmail.com
// @license.name MIT License
// @license.url https://github.com/mrinjamul/mrinjamul-auth/blob/main/LICENSE
// @host localhost:8080
// @BasePath /
// @schemes http

var (
	// StartTime is the time when the server started
	StartTime time.Time
	// BootTime is the time when the server booted
	BootTime time.Duration
)

// InitRoutes initializes the routes
func InitRoutes(router *gin.Engine) {
	// Initialize services
	svc := services.NewServices()

	// Initialize the routes

	// Backend API

	docs.SwaggerInfo.BasePath = "/"
	// health check
	router.GET("/api/health", func(ctx *gin.Context) {
		svc.HealthCheckService().HealthCheck(ctx, StartTime, BootTime)
	})

	v1 := router.Group("/api/v1")
	{
		// auth is for authentication endpoint
		auth := v1.Group("auth")
		{
			auth.POST("/signup", func(ctx *gin.Context) {
				svc.AuthService().Register(ctx)
			})
			auth.POST("/login", func(ctx *gin.Context) {
				svc.AuthService().Login(ctx)
			})
			auth.POST("/refresh", func(ctx *gin.Context) {
				svc.AuthService().RefreshToken(ctx)
			})
		}

		// user is for user endpoint
		user := v1.Group("user")
		{
			user.GET("/:username", func(ctx *gin.Context) {
				svc.AuthService().View(ctx)
			})
			user.PUT("/:username", func(ctx *gin.Context) {
				svc.AuthService().Update(ctx)
			})
			user.DELETE("/:username", func(ctx *gin.Context) {
				svc.AuthService().Delete(ctx)
			})
		}

	}
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
}
