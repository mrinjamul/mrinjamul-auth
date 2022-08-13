package services

import (
	"github.com/mrinjamul/mrinjamul-auth/api/controllers"
	"github.com/mrinjamul/mrinjamul-auth/database"
	"github.com/mrinjamul/mrinjamul-auth/repository"
)

type Services interface {
	HealthCheckService() controllers.HealthCheck
	AuthService() controllers.User
}

type services struct {
	healthCheck controllers.HealthCheck
	auth        controllers.User
}

func (svc *services) HealthCheckService() controllers.HealthCheck {
	return svc.healthCheck
}

func (svc *services) AuthService() controllers.User {
	return svc.auth
}

// NewServices initializes services
func NewServices() Services {
	db := database.GetDB()
	return &services{
		healthCheck: controllers.NewHealthCheck(),
		auth: controllers.NewUser(
			repository.NewUserRepo(db),
		),
	}
}
