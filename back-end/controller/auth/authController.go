package auth

import (
	"net/http"
	"os"
	"service/auth"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthStatusPayload struct {
	Message string `json:status`
}

type AuthController struct {
	authService *auth.AuthService
}

func NewAuthController(authService *auth.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

func (c *AuthController) LoginEndpoint(ctx *gin.Context) {
	var loginBody auth.LoginBody

	// validate the incoming body
	if err := ctx.ShouldBindJSON(&loginBody); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, err)
		return
	}

	token, err := c.authService.Login(loginBody)

	if err != nil {
		status := AuthStatusPayload{Message: err.Error()}

		ctx.AbortWithStatusJSON(http.StatusInternalServerError, status)
		return
	}

	ctx.SetCookie("Authorization", "Bearer " + token, int((time.Hour * 24 * 7).Seconds()), "", "", os.Getenv("ENV") == "prod", true)
	ctx.JSON(http.StatusOK,	AuthStatusPayload{Message: "success"})
}

func (c *AuthController) RegisterEndpoint(ctx *gin.Context) {
	var registerBody auth.RegisterBody

	if err := ctx.ShouldBindJSON(&registerBody); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, err)
		return
	}

	err := c.authService.Register(registerBody)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, AuthStatusPayload{Message: err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, AuthStatusPayload{Message: "success"})
}
