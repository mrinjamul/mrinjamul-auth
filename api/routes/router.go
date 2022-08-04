package routes

import (
	"time"

	"github.com/gin-gonic/gin"
)

var (
	// StartTime is the time when the server started
	StartTime time.Time
	// BootTime is the time when the server booted
	BootTime time.Duration
)

// InitRoutes initializes the routes
func InitRoutes(router *gin.Engine) {

	// Initialize the routes
	// API Routes
	api := router.Group("/api")
	{
		api.GET("/health", func(ctx *gin.Context) {
			ctx.JSON(200, gin.H{
				"status":     "ok",
				"start_time": StartTime,
				"boot_time":  BootTime,
			})
		})
	}
}
