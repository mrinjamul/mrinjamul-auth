package routes

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mrinjamul/mrinjamul-auth/api/services"
)

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

	// health check
	router.GET("/api/health", func(ctx *gin.Context) {
		svc.HealthCheckService().HealthCheck(ctx, StartTime, BootTime)
	})

	// auth is for authentication endpoint
	auth := router.Group("auth")
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
	user := router.Group("user")
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

	api := router.Group("/api")
	{
		api.GET("/ping", func(ctx *gin.Context) {
			ctx.JSON(200, gin.H{
				"message": "pong",
			})
		})
	}
}
