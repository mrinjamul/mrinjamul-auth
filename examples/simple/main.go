package main

import (
	"crypto/ecdsa"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/mrinjamul/mrinjamul-auth/middleware"
	"github.com/mrinjamul/mrinjamul-auth/models"
	"github.com/mrinjamul/mrinjamul-auth/utils"
)

var (
	// verifyKey is the key used to verify JWT tokenss
	verifyKey *ecdsa.PublicKey
)

func init() {
	// Load secret keys

	// public key
	publicKeyPath := utils.GetEnv("PUBLIC_KEY")
	if publicKeyPath == "" {
		log.Println("PUBLIC_KEY is not set")
	}
	publicKey, err := utils.ReadSecretKey(publicKeyPath)
	if err != nil {
		log.Println(err)
	}
	verifyKey, err = jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Println(err)
	}
}

func main() {
	router := gin.Default()

	// Query string parameters are parsed using the existing underlying request object.
	// The request responds to a url matching:  /welcome?firstname=Jane&lastname=Doe
	router.GET("/welcome", middleware.JWTAuth(), func(c *gin.Context) {
		var username string
		// Get JWT token
		tokenString, err := c.Cookie("token")
		if err != nil {
			tkn, _ := utils.ParseToken(c.Request.Header.Get("Authorization"))
			tokenString = tkn
		}
		claims := &models.Claims{}
		token, _ := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})
		if token != nil {
			username = claims.Username
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome " + username,
		})
	})
	router.Run(":8081")
}
