package auth

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type LoginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required"`
}

type AuthService struct {
	// Dependencies can be added here
	// TODO - replace with database connection
	repository map[string]RegisterBody // username->user
}

func NewAuthService() *AuthService {
	return &AuthService{repository: make(map[string]RegisterBody)}
}

func (s *AuthService) Login(b LoginBody) (string, error) {
	// Implementation of login service

	user, exists := s.repository[b.Username]

	if !exists {
		return "", errors.New("user does not exist")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(b.Password)); err != nil {
		return "", errors.New("invalid password")
	}

	// sign a new token with private key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24),
		"iss": os.Getenv("URL"),
		"sub": user.Username,
		"roles": []string{
			"user",
		},
		"email":     user.Email,
		"timestamp": time.Now().Add(time.Hour * 24 * 7).Unix(),
	})
	tokenString, signErr := token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))

	if signErr != nil {
		return "", signErr
	}

	// return the signed token string
	return tokenString, nil
}

func (s *AuthService) Register(b RegisterBody) error {

	// check if user already exists
	_, exists := s.repository[b.Username]

	if exists {
		return errors.New("user already exists")
	}

	// hash the password
	pass, err := bcrypt.GenerateFromPassword([]byte(b.Password), 10)

	if err != nil {
		return err
	}

	// store the hashed password
	b.Password = string(pass)

	// store in DB
	s.repository[b.Username] = b

	return nil
}
