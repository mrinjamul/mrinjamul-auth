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
	"github.com/golang-jwt/jwt/v4"
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

	// private key
	privateKeyPath := utils.GetEnv("PRIVATE_KEY")
	privateKey, err := utils.ReadSecretKey(privateKeyPath)
	if err != nil {
		log.Println(err)
	}
	signingKey, err = jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Println(err)
	}

	// public key
	publicKeyPath := utils.GetEnv("PUBLIC_KEY")
	publicKey, err := utils.ReadSecretKey(publicKeyPath)
	if err != nil {
		log.Println(err)
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

// Register creates a new user
func (u *user) Register(ctx *gin.Context) {
	var user models.User
	// Get the JSON body and decode into user struct
	err := ctx.BindJSON(&user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "bad request",
		})
		ctx.Abort()
		return
	}

	// check if valid username
	if !utils.IsValidUserName(*user.Username) {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid username",
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
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad request",
			"message": "bad password",
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
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
		})
		ctx.Abort()
		return
	}

	// Create the user
	err = u.userRepo.CreateUser(&user)
	if err != nil {
		ctx.JSON(http.StatusConflict, gin.H{
			"error": err.Error(),
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
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal Server Error",
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
	ctx.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "user created successfully",
		"user":    user,
	})
}

// Login logs in a user
func (u *user) Login(ctx *gin.Context) {
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
	if (creds.Email == "" && creds.Username == "") || creds.Password == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "email or password cannot be empty",
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
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid credentials",
			})
			ctx.Abort()
			return
		}
	}

	// if user is deleted then return unauthorized
	if user.DeletedAt.Valid {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "user is deleted",
		})
		ctx.Abort()
		return
	}

	// Validate the password
	valid := utils.VerifyHash(creds.Password, *user.Password)
	if !valid {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid Password",
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
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status": "success",
		"token":  tokenString,
	})

}

// RefreshToken refreshes the token
func (u *user) RefreshToken(ctx *gin.Context) {
	// Get JWT token
	tokenString, err := ctx.Cookie("token")
	if err != nil {
		tkn, err := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
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
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid token",
		})
		ctx.Abort()
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			ctx.Abort()

			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "bad token",
		})
		ctx.Abort()
		return
	}
	// check if token is expired
	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "token expired",
		})
		ctx.Abort()
		return
	}

	// Dont refresh if token is not expired
	if time.Until(claims.ExpiresAt.Time) > 2*time.Hour {
		ctx.JSON(http.StatusOK, gin.H{
			"status": "success",
			"token":  tokenString,
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
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
		})
		ctx.Abort()
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"status": "success",
		"token":  tokenString,
	})
}

// View returns the public user details
func (u *user) View(ctx *gin.Context) {
	// get the username param from context
	username := ctx.Param("username")
	// get the user from the database
	user, err := u.userRepo.GetUserByUsername(username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
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
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token",
				})
				ctx.Abort()
				return
			}
			user, err := u.userRepo.GetUserByUsername(claims.Username)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{
					"error": "Internal Server Error",
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
			ctx.JSON(http.StatusOK, gin.H{
				"status": "success",
				"user":   user,
			})
			return
		}
		// if user is found, return the user info
		user = models.User{
			Username:  user.Username,
			FirstName: user.FirstName,
			CreatedAt: user.CreatedAt,
		}
		ctx.JSON(http.StatusOK, gin.H{
			"status": "success",
			"user":   user,
		})
	} else {
		// if user is not found, return error
		ctx.JSON(http.StatusNotFound, gin.H{
			"status": "user not found",
			"user":   "",
		})
	}
}

// Update updates the user details
func (u *user) Update(ctx *gin.Context) {
	// get the username param from context
	username := ctx.Param("username")

	// get the user from the database
	user, err := u.userRepo.GetUserByUsername(username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
		})
		ctx.Abort()
		return
	}

	// Parse the JSON body
	var userUpdate models.User
	err = ctx.BindJSON(&userUpdate)
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

	// set non empty fields to user struct
	if *userUpdate.FirstName != "" {
		user.FirstName = userUpdate.FirstName
	}
	if *userUpdate.MiddleName != "" {
		user.MiddleName = userUpdate.MiddleName
	}
	if *userUpdate.LastName != "" {
		user.LastName = userUpdate.LastName
	}
	if *userUpdate.DOB != "" {
		user.DOB = userUpdate.DOB
	}
	if *userUpdate.Email != "" {
		user.Email = userUpdate.Email
	}
	if *userUpdate.Password != "" {
		user.Password = userUpdate.Password
	}
	// if *userUpdate.Username != "" {
	// 	user.Username = userUpdate.Username
	// }
	// Update the user
	err = u.userRepo.UpdateUser(&user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
		})
		ctx.Abort()
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User updated successfully",
		// "token":   tokenString,
		"user": user,
	})

}

// Delete deletes a user
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
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
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
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal Server Error",
		})
		ctx.Abort()
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User deleted successfully",
	})
}

// NewUser initializes a new user controller
func NewUser(userRepo repository.UserRepo) User {
	return &user{
		userRepo: userRepo,
	}
}
