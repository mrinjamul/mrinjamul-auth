package controllers

// Create a authentication system using JWT
// To implement Multi-level Authentication

import (
	"crypto/ecdsa"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mrinjamul/mrinjamul-auth/config"
	"github.com/mrinjamul/mrinjamul-auth/models"
	"github.com/mrinjamul/mrinjamul-auth/repository"
	"github.com/mrinjamul/mrinjamul-auth/utils"
)

var (
	// signingKey is the key used to sign JWT tokens
	signingKey *ecdsa.PrivateKey
	// verifyKey is the key used to verify JWT tokenss
	verifyKey *ecdsa.PublicKey
)

func init() {
	// Load secret keys
	cfg := config.GetConfig()
	// private key
	privateKey, err := utils.ReadSecretKey(cfg.Server.PrivateKey)
	if err != nil {
		log.Println(err)
	}
	if privateKey == nil {
		panic("PRIVATE_KEY is not set")
	}
	signingKey, err = jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Println(err)
	}

	// public key
	publicKey, err := utils.ReadSecretKey(cfg.Server.PublicKey)
	if err != nil {
		log.Println(err)
	}
	if publicKey == nil {
		panic("PUBLIC_KEY is not set")
	}
	verifyKey, err = jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Println(err)
	}
}

// User is a controller for users
type User interface {
	// Register creates a new user
	Register(ctx *gin.Context)
	// Login logs in a user
	Login(ctx *gin.Context)
	// RefreshToken refreshes the token
	RefreshToken(ctx *gin.Context)
	// Logout logs out a user
	Logout(ctx *gin.Context)
	// View returns the public or private user details
	View(ctx *gin.Context)
	// Update updates the user details
	Update(ctx *gin.Context)
	// Delete deletes a user
	Delete(ctx *gin.Context)
}

// user is a controller for users
type user struct {
	userRepo repository.UserRepo
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user
// @ID register
// @Tags auth
// @Accept  json
// @Produce  json
// @Param user body models.User true "User"
// @Success 200 {object} models.User
// @Failure 400 {object} models.Error
// @Failure 409 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/auth/signup [post]
func (u *user) Register(ctx *gin.Context) {
	var user models.User
	// Get the JSON body and decode into user struct
	err := ctx.BindJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "BadRequest",
				Code:    "BadRequest",
				Message: "Invalid JSON body",
			},
		})
		ctx.Abort()
		return
	}

	// check if valid username
	if !utils.IsValidUserName(*user.Username) {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "Invalid",
				Code:    "InvalidRequestData",
				Param:   "username",
				Message: "Username is invalid",
			},
		})
		ctx.Abort()
		return
	}
	*user.Username = strings.ToLower(*user.Username)
	*user.Username = strings.TrimSpace(*user.Username)

	// check if valid email
	*user.Email = strings.ToLower(*user.Email)
	*user.Email = strings.TrimSpace(*user.Email)

	// Validate Password
	ok := utils.IsValidPassword(*user.Password)
	if !ok {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "Invalid",
				Code:    "InvalidRequestData",
				Param:   "password",
				Message: "Password is invalid",
			},
		})
		ctx.Abort()
		return
	}
	role := "user"
	user.Role = &role
	accessLevel := 1
	user.Level = &accessLevel

	// Hash the password before storing
	*user.Password, err = utils.HashAndSalt(*user.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}

	// Create the user
	err = u.userRepo.CreateUser(&user)
	if err != nil {
		ctx.JSON(http.StatusConflict, models.Error{
			Error: models.ServiceError{
				Kind:    "Conflict",
				Code:    "Conflict",
				Message: "User already exists",
			},
		})
		return
	}

	// First User will be admin
	if user.ID == 1 {
		role = "admin"
		user.Role = &role
		accessLevel = 4
		user.Level = &accessLevel
		err = u.userRepo.UpdateUser(&user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, models.Error{
				Error: models.ServiceError{
					Kind:    "Internal",
					Code:    "InternalServerError",
					Message: err.Error(),
				},
			})
		}
	}

	user = models.User{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		FirstName:  user.FirstName,
		MiddleName: user.MiddleName,
		LastName:   user.LastName,
		DOB:        user.DOB,
		CreatedAt:  user.CreatedAt,
		DeletedAt:  user.DeletedAt,
	}
	ctx.JSON(http.StatusOK, user)
}

// Login godoc
// @Summary Login a user
// @Description Login a user
// @ID login
// @Tags auth
// @Accept  json
// @Produce  json
// @Param user body models.Credentials true "User"
// @Success 200 {object} models.Token
// @Failure 400 {object} models.Error
// @Failure 401 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/auth/login [post]
func (u *user) Login(ctx *gin.Context) {
	var creds models.Credentials
	var user models.User
	// Get the JSON body and decode into creds struct
	err := ctx.BindJSON(&creds)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "Invalid",
				Code:    "InvalidRequestData",
				Message: "invalid body",
			},
		})
		return
	}
	if (creds.Email == "" && creds.Username == "") || creds.Password == "" {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "BadRequest",
				Code:    "BadRequest",
				Message: "username and password are required",
			},
		})
		return
	}

	// trim spaces in creds
	creds.Username = strings.TrimSpace(creds.Username)
	creds.Email = strings.TrimSpace(creds.Email)

	// Get the expected password from the database
	user, err = u.userRepo.GetUserByUsername(creds.Username)
	if err != nil || user.ID == 0 {
		user, err = u.userRepo.GetUserByEmail(creds.Email) // error
		if err != nil {
			ctx.JSON(http.StatusBadRequest, models.Error{
				Error: models.ServiceError{
					Kind:    "BadRequest",
					Code:    "BadRequest",
					Param:   "username or email",
					Message: "Invalid username or email",
				},
			})
			ctx.Abort()
			return
		}
	}

	// if user is deleted then return unauthorized
	if user.DeletedAt.Valid {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Message: "User is deleted",
			},
		})
		ctx.Abort()
		return
	}

	// Validate the password
	valid := utils.VerifyHash(creds.Password, *user.Password)
	if !valid {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Param:   "password",
				Message: "Invalid password",
			},
		})
		ctx.Abort()
		return
	}

	// expires in  24 hours
	issuedAt := time.Now()
	expiresAt := time.Now().Add(24 * time.Hour)
	// Create the JWT claims, which includes the username and expiry time
	claims := &models.Claims{
		Username: creds.Username,
		Role:     *user.Role,
		Level:    *user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(issuedAt),
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	// Create the JWT
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		return
	}
	// SET COOKIE
	ctx.SetCookie("token", tokenString, 3600, "/", "", false, true)

	ctx.JSON(http.StatusOK, models.Token{
		Token: tokenString,
	})

}

// RefreshToken godoc
// @Summary Refresh a token
// @Description Refresh a token
// @ID refresh-token
// @Tags auth
// @Accept  json
// @Produce  json
// @Param token header string true "Token"
// @Success 200 {object} models.Token
// @Failure 400 {object} models.Error
// @Failure 401 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/auth/refresh [post]
func (u *user) RefreshToken(ctx *gin.Context) {
	// Get JWT token
	tokenString, err := ctx.Cookie("token")
	if err != nil {
		tkn, err := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, models.Error{
				Error: models.ServiceError{
					Kind:    "Unauthorized",
					Code:    "Unauthorized",
					Message: "Invalid token",
				},
			})
			ctx.Abort()
			return
		}
		tokenString = tkn
	}
	claims := &models.Claims{}
	token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if !token.Valid {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Message: "Invalid token",
			},
		})
		ctx.Abort()
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			ctx.JSON(http.StatusUnauthorized, models.Error{
				Error: models.ServiceError{
					Kind:    "Unauthorized",
					Code:    "Unauthorized",
					Message: "Invalid token",
				},
			})
			ctx.Abort()

			return
		}
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "BadRequest",
				Code:    "BadToken",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	// check if token is expired
	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Message: "Token is expired",
			},
		})
		ctx.Abort()
		return
	}

	// Dont refresh if token is not expired
	if time.Until(claims.ExpiresAt.Time) > 2*time.Hour {
		ctx.JSON(http.StatusOK, models.Token{
			Token: tokenString,
		})
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	issuedAt := time.Now()
	// expires in  24 hours
	expiresAt := time.Now().Add(24 * time.Hour)
	claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	// Declare the token with the algorithm used for signing, and the claims
	token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Create the JWT string
	tokenString, err = token.SignedString(signingKey)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	// SET COOKIE
	ctx.SetCookie("token", tokenString, 3600, "/", "", false, true)

	ctx.JSON(http.StatusOK, models.Token{
		Token: tokenString,
	})
}

// Logout godoc
// @Summary Logout a user
// @Description Logout a user
// @ID logout
// @Tags auth
// @Produce  json
// @Success 200 {object} string
// @Failure 500 {object} string
// @Router /api/v1/auth/logout [get]
func (u *user) Logout(ctx *gin.Context) {
	// check if cookie is present
	_, err := ctx.Cookie("token")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "Not logged in",
		})
		ctx.Abort()
		return
	}
	// SET COOKIE
	ctx.SetCookie("token", "", -1, "/", "", false, true)
	ctx.JSON(http.StatusOK,
		gin.H{
			"message": "Logged out successfully",
		},
	)
}

// View godoc
// @Summary Get user details
// @Description Get user details
// @ID get-user
// @Tags user
// @Accept  json
// @Produce  json
// @Param token header string true "Token"
// @Param username path string true "Username"
// @Success 200 {object} models.User
// @Failure 400 {object} models.Error
// @Failure 401 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/user/{username} [get]
func (u *user) View(ctx *gin.Context) {
	// get the username param from context
	username := ctx.Param("username")
	// get the user from the database
	user, err := u.userRepo.GetUserByUsername(username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	// Get JWT token
	tokenString, err := ctx.Cookie("token")
	if err != nil {
		tkn, _ := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
		tokenString = tkn
	}

	// check if user is found or not
	if user.ID > 0 && !user.DeletedAt.Valid {
		if tokenString != "" {
			claims := &models.Claims{}
			token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})
			if !token.Valid {
				ctx.JSON(http.StatusUnauthorized, models.Error{
					Error: models.ServiceError{
						Kind:    "Unauthorized",
						Code:    "Unauthorized",
						Message: "Invalid token",
					},
				})
				ctx.Abort()
				return
			}
			user, err := u.userRepo.GetUserByUsername(claims.Username)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, models.Error{
					Error: models.ServiceError{
						Kind:    "Internal",
						Code:    "InternalServerError",
						Message: err.Error(),
					},
				})
				ctx.Abort()
				return
			}

			user = models.User{
				ID:         user.ID,
				Username:   user.Username,
				Email:      user.Email,
				FirstName:  user.FirstName,
				MiddleName: user.MiddleName,
				LastName:   user.LastName,
				DOB:        user.DOB,
				Role:       user.Role,
				CreatedAt:  user.CreatedAt,
				DeletedAt:  user.DeletedAt,
			}
			ctx.JSON(http.StatusOK, user)
			return
		}
		// if user is found, return the user info
		user = models.User{
			Username:  user.Username,
			FirstName: user.FirstName,
			CreatedAt: user.CreatedAt,
		}
		ctx.JSON(http.StatusOK, user)
	} else {
		// if user is not found, return error
		ctx.JSON(http.StatusNotFound, models.Error{
			Error: models.ServiceError{
				Kind:    "NotFound",
				Code:    "NotFound",
				Message: "User not found",
			},
		})
	}
}

// Update godoc
// @Summary Update user details
// @Description Update user details
// @ID update-user
// @Tags user
// @Accept  json
// @Produce  json
// @Param token header string true "Token"
// @Param username path string true "Username"
// @Param user body models.User true "User"
// @Success 200 {object} models.User
// @Failure 400 {object} models.Error
// @Failure 401 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/user/{username} [put]
func (u *user) Update(ctx *gin.Context) {
	// get the username param from context
	username := ctx.Param("username")

	// get the user from the database
	user, err := u.userRepo.GetUserByUsername(username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}

	// Parse the JSON body
	var userUpdate models.User
	err = ctx.BindJSON(&userUpdate)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, models.Error{
			Error: models.ServiceError{
				Kind:    "BadRequest",
				Code:    "BadRequest",
				Message: "Invalid JSON body",
			},
		})
		return
	}

	// Get JWT token
	tokenString, err := ctx.Cookie("token")
	if err != nil {
		tkn, _ := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
		tokenString = tkn
	}
	claims := &models.Claims{}
	token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if !token.Valid {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Message: "Invalid token",
			},
		})
		ctx.Abort()
		return
	}

	// check if username is same as the one in the token
	if claims.Username != username {
		ctx.JSON(http.StatusUnauthorized, models.Error{
			Error: models.ServiceError{
				Kind:    "Unauthorized",
				Code:    "Unauthorized",
				Message: "permission denied",
			},
		})
		ctx.Abort()
		return
	}

	// set non empty fields to user struct
	if userUpdate.FirstName != nil {
		user.FirstName = userUpdate.FirstName
	}
	if userUpdate.MiddleName != nil {
		user.MiddleName = userUpdate.MiddleName
	}
	if userUpdate.LastName != nil {
		user.LastName = userUpdate.LastName
	}
	if userUpdate.DOB != nil {
		user.DOB = userUpdate.DOB
	}
	if userUpdate.Email != nil {
		user.Email = userUpdate.Email
	}
	if userUpdate.Password != nil {
		// Validate Password
		ok := utils.IsValidPassword(*user.Password)
		if !ok {
			ctx.JSON(http.StatusBadRequest, models.Error{
				Error: models.ServiceError{
					Kind:    "BadRequest",
					Code:    "BadRequest",
					Message: "Invalid password",
				},
			})
			ctx.Abort()
			return
		}
		// Hash the password before storing
		*user.Password, err = utils.HashAndSalt(*userUpdate.Password)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, models.Error{
				Error: models.ServiceError{
					Kind:    "Internal",
					Code:    "InternalServerError",
					Message: err.Error(),
				},
			})
			ctx.Abort()
			return
		}
	}
	// if *userUpdate.Username != "" {
	// 	user.Username = userUpdate.Username
	// }
	// Update the user
	err = u.userRepo.UpdateUser(&user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	user.Password = nil
	user.Level = nil
	ctx.JSON(http.StatusOK, user)
}

// Delete godoc
// @Summary Delete user
// @Description Delete a user
// @ID delete-user
// @Tags user
// @Accept  json
// @Produce  json
// @Param token header string true "Token"
// @Param username path string true "Username"
// @Param user body models.Credentials true "User"
// @Success 200 {object} models.Message
// @Failure 400 {object} models.Error
// @Failure 401 {object} models.Error
// @Failure 500 {object} models.Error
// @Router /api/v1/user/{username} [delete]
func (u *user) Delete(ctx *gin.Context) {
	// get the username param from context
	username := ctx.Param("username")

	var creds models.Credentials
	var user models.User

	// Get the JSON body and decode into creds struct
	err := ctx.BindJSON(&creds)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Get JWT token
	tokenString, err := ctx.Cookie("token")
	if err != nil {
		tkn, _ := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
		tokenString = tkn
	}
	claims := &models.Claims{}
	token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if !token.Valid {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid token",
		})
		ctx.Abort()
		return
	}

	// check if username is same as the one in the token
	if claims.Username != username {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid token",
		})
		ctx.Abort()
		return
	}

	user, err = u.userRepo.GetUserByUsername(claims.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	// Verify the password before deleting the user
	if creds.Password == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "password is required",
		})
		ctx.Abort()
		return
	}
	valid := utils.VerifyHash(creds.Password, *user.Password)
	if !valid {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid Password",
		})
		ctx.Abort()
		return
	}

	err = u.userRepo.DeleteUser(user.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, models.Error{
			Error: models.ServiceError{
				Kind:    "Internal",
				Code:    "InternalServerError",
				Message: err.Error(),
			},
		})
		ctx.Abort()
		return
	}
	ctx.JSON(http.StatusOK, models.Message{
		Code:    "Success",
		Message: "User deleted successfully",
	})
}

// NewUser initializes a new user controller
func NewUser(userRepo repository.UserRepo) User {
	return &user{
		userRepo: userRepo,
	}
}
