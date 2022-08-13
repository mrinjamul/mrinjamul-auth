package repository

import (
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/mrinjamul/mrinjamul-auth/models"
	"gorm.io/gorm"
)

// UserRepo is a repository for users
type UserRepo interface {
	// CreateUser creates a new user
	CreateUser(user *models.User) error
	// GetUserByID returns a user by id
	GetUser(id int) (models.User, error)
	// GetUsers returns all users
	GetUsers() ([]models.User, error)
	// GetUserByUsername returns a user by username
	GetUserByUsername(username string) (models.User, error)
	// GetUserByEmail returns a user by email
	GetUserByEmail(email string) (models.User, error)
	// UpdateUser updates an existing user
	UpdateUser(user *models.User) error
	// DeleteUser deletes an existing user
	DeleteUser(id uint) error
}

// userRepo is a repository for users
type userRepo struct {
	db gorm.DB
}

// CreateUser creates a new user
func (u *userRepo) CreateUser(user *models.User) error {
	// check if user already exists
	var exists bool
	err := u.db.
		Model(models.User{}).
		Select("count(*) > 0").
		Where("username = ?", user.Username).
		Find(&exists).Error
	if err != nil {
		return err
	}
	if exists {
		return errors.New("user already exists")
	}
	err = u.db.
		Model(models.User{}).
		Select("count(*) > 0").
		Where("email = ?", user.Email).
		Find(&exists).Error
	if err != nil {
		return err
	}
	if exists {
		return errors.New("user already exists")
	}

	// create user
	err = u.db.Create(&user).Error
	if err != nil {
		return err
	}
	return nil
}

// GetUser returns a user by id
func (u *userRepo) GetUser(id int) (models.User, error) {
	var user models.User
	err := u.db.Where("id = ?", id).First(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// GetUsers returns all users
func (u *userRepo) GetUsers() ([]models.User, error) {
	var users []models.User
	err := u.db.Find(&users).Error
	if err != nil {
		return nil, err
	}
	return users, nil
}

// GetUserByUsername returns a user by username
func (u *userRepo) GetUserByUsername(username string) (models.User, error) {
	var user models.User
	err := u.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// GetUserByEmail returns a user by email
func (u *userRepo) GetUserByEmail(email string) (models.User, error) {
	var user models.User
	err := u.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

// UpdateUser updates an existing user
func (u *userRepo) UpdateUser(user *models.User) error {
	err := u.db.Save(&user).Error
	if err != nil {
		return err
	}
	return nil
}

// DeleteUser deletes an existing user
func (u *userRepo) DeleteUser(id uint) error {
	// int to string conversion
	idStr := strconv.Itoa(int(id))
	emStr := idStr + "@localhost"
	user := models.User{
		ID:       id,
		Username: &idStr,
		Email:    &emStr,
		DeletedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}
	err := u.db.Save(&user).Error
	if err != nil {
		return err
	}
	return nil
}

// NewUserRepo initializes a new user repository
func NewUserRepo(db *gorm.DB) UserRepo {
	return &userRepo{
		db: *db,
	}
}
