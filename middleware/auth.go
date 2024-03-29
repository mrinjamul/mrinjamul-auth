package middleware

import (
	"crypto/ecdsa"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
	var publicKey []byte
	var err error
	publicKeyPath := utils.GetEnv("PUBLIC_KEY")
	if publicKeyPath == "" {
		log.Println("PUBLIC_KEY is not set")
	} else {
		publicKey, err = utils.ReadSecretKey(publicKeyPath)
		if err != nil {
			log.Println(err)
		}
	}

	verifyKey, err = jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Println(err)
	}
}

// JWTAuth is a middleware for validating JWT tokens
func JWTAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// check if token is present
		// Get cookie "token"
		tokenString, err := ctx.Cookie("token")
		if err != nil {
			tkn, err := utils.ParseToken(ctx.Request.Header.Get("Authorization"))
			if err != nil {
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"error": "no token provided",
				})
				ctx.Abort()
				return
			}
			tokenString = tkn
		}

		claims := &models.Claims{}
		// check if token is expired
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
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
		ctx.Next()
	}
}

// JWTAuth is a middleware for validating JWT tokens
func JWTAuthAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// check if token is present
		// Get cookie "token"
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
		// check if token is expired
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
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

		// check if user is admin
		if claims.Role != "admin" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}
