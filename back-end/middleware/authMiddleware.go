package auth

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type TokenError struct {
	message string
}

func getTokenFromBearer(token string) (string, error) {
	if token[:7] != "Bearer " {
		return "", errors.New("invalid token format")
	}
	return token[7:], nil
}

func VerifyToken(ctx *gin.Context) {
	// get token from cookie
	userToken, err := ctx.Cookie("Authorization")
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, TokenError{message: "token not found"})
		return
	}

	// parse token
	userToken, bearerError := getTokenFromBearer(userToken)
	if bearerError != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, TokenError{message: bearerError.Error()})
		return
	}

	token, authErr := jwt.Parse(userToken, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("Invalid signing method", jwt.ValidationErrorSignatureInvalid)
		}

		var secKey string = os.Getenv("JWT-SECRET-KEY")

		// Replace with your actual secret key
		return []byte(secKey), nil
	})

	if authErr != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusForbidden, TokenError{message: "Not Authorized"})
		return
	}

	// Add claims to context if needed
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// You can access claims and set them in context
		ctx.Set("user", claims["email"])
		ctx.Set("userId", claims["userId"])
	}

	ctx.Next()
}
