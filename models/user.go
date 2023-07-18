package models

import (
	"database/sql"
	"time"
)

// User is a user of the application
type User struct {
	ID         uint         `json:"id,omitempty" gorm:"primary_key,autoIncrement,not null"`
	UID        string       `json:"uid,omitempty" gorm:"unique,not null"`
	FirstName  *string      `json:"first_name,omitempty" gorm:"not null"`
	MiddleName *string      `json:"middle_name,omitempty"`
	LastName   *string      `json:"last_name,omitempty" gorm:"not null"`
	Username   *string      `json:"username"  gorm:"unique,not null"`
	Email      *string      `json:"email" gorm:"unique"`
	DOB        *string      `json:"dob,omitempty" gorm:""`
	Password   *string      `json:"password,omitempty" gorm:"not null"`
	Role       *string      `json:"role,omitempty" gorm:"not null"`
	Level      *int         `json:"level,omitempty" gorm:"not null"`
	CreatedAt  time.Time    `json:"created_at" gorm:"not null"`
	UpdatedAt  time.Time    `json:"updated_at" gorm:"not null"`
	DeletedAt  sql.NullTime `json:"deleted_at" gorm:"index,not null"`
}
