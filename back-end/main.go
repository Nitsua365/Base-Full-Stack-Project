package main

import (
	"log"
	"os"
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"controller/auth"
	mw "middleware"
	serviceAuth "service/auth"
)

func main() {
	// Parse the "-release" flag using the flag library
	releaseMode := flag.Bool("release", false, "Run in release mode")
	flag.Parse()

	var env_file string = ".env.dev"

	// Set the gin mode to release if the flag is set
	if *releaseMode {
		gin.SetMode(gin.ReleaseMode)
		env_file = ".env.prod"
	}

	// initialize the gin app
	app := gin.New()

	// Load the .env
	err := godotenv.Load(env_file)
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
		os.Exit(1)
	}

	// Initialize services, and controllers
	authService := serviceAuth.NewAuthService()
	authController := auth.NewAuthController(authService)

	// API routes
	apiV1 := app.Group("/api/v1")

	// Auth routes
	authGroup := apiV1.Group("/auth")
	{
		authGroup.POST("/login", authController.LoginEndpoint)
		authGroup.POST("/register", authController.RegisterEndpoint)
	}

	testGroup := apiV1.Group("test")
	{
		testGroup.GET("/", mw.VerifyToken, func(ctx *gin.Context) {
			ctx.JSON(200, gin.H{
				"message": "You are Authorized",
			})
		})
	}

	// TODO - add payment
	// payment := app.Group("/payment")

	// Run the server on port 3000
	app.Run(fmt.Sprintf(":%s", os.Getenv("PORT")))
}
