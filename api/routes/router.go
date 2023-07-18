package routes

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mrinjamul/mrinjamul-auth/api/services"
	docs "github.com/mrinjamul/mrinjamul-auth/docs"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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
	// Add CORS middleware
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	router.Use(cors.New(config))

	// Initialize the routes

	// Home Page
	router.GET("/", func(ctx *gin.Context) {
		svc.View().Index(ctx)
	})

	// About Page
	router.GET("/about", func(ctx *gin.Context) {
		svc.View().About(ctx)
	})

	// Health Check
	// router.GET("/stats", func(ctx *gin.Context) {
	// 	svc.View().Stats(ctx)
	// })

	// 404 Page
	router.NoRoute(func(ctx *gin.Context) {
		svc.View().NotFound(ctx)
	})

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
			auth.GET("/logout", func(ctx *gin.Context) {
				svc.AuthService().Logout(ctx)
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
