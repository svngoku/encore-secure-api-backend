package authapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
	"encore.dev/storage/sqldb"
	"golang.org/x/crypto/bcrypt"
)

// Define the database
var db = sqldb.NewDatabase("authapi", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// UserID type for auth
type UserID string

// User represents a user in the database
type User struct {
	ID       int64  `sql:"id"`
	Email    string `sql:"email"`
	Password string `sql:"password"`
	APIKey   string `sql:"api_key"`
}

// SignupParams for account creation
type SignupParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupResponse with the generated API key
type SignupResponse struct {
	APIKey string `json:"api_key"`
}

// LoginParams for user authentication
type LoginParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse contains the API key
type LoginResponse struct {
	APIKey string `json:"api_key"`
}

// RegenerateKeyResponse contains the new API key
type RegenerateKeyResponse struct {
	NewAPIKey string `json:"new_api_key"`
}

// generateAPIKey generates a unique API key with the prefix "esk_"
func generateAPIKey() (string, error) {
	// Generate 16 bytes of random data (32 characters when hex-encoded)
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "esk_" + hex.EncodeToString(bytes), nil
}

//encore:api public method=POST path=/signup
func Signup(ctx context.Context, params *SignupParams) (*SignupResponse, error) {
	// Validate input
	if params.Email == "" || !strings.Contains(params.Email, "@") {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "valid email is required",
		}
	}
	if params.Password == "" || len(params.Password) < 8 {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "password must be at least 8 characters",
		}
	}

	// Hash password
	hashedPw, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		rlog.Error("failed to hash password", "error", err)
		return nil, &errs.Error{
			Code:    errs.Internal,
			Message: "failed to hash password",
		}
	}

	// Generate API key
	apiKey, err := generateAPIKey()
	if err != nil {
		rlog.Error("failed to generate API key", "error", err)
		return nil, &errs.Error{
			Code:    errs.Internal,
			Message: "failed to generate API key",
		}
	}

	// Insert user into database
	result, err := db.Exec(ctx, `
		INSERT INTO users (email, password, api_key)
		VALUES ($1, $2, $3)
		ON CONFLICT (email) DO NOTHING
	`, params.Email, string(hashedPw), apiKey)
	if err != nil {
		rlog.Error("database insert failed", "error", err, "email", params.Email)
		return nil, &errs.Error{
			Code:    errs.Internal,
			Message: fmt.Sprintf("failed to create user: %v", err),
		}
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return nil, &errs.Error{
			Code:    errs.AlreadyExists,
			Message: "email already registered",
		}
	}

	// Return the API key directly since we just created it
	return &SignupResponse{APIKey: apiKey}, nil
}

//encore:api public method=POST path=/login
func Login(ctx context.Context, params *LoginParams) (*LoginResponse, error) {
	if params.Email == "" || params.Password == "" {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "email and password required",
		}
	}

	var user User
	err := db.QueryRow(ctx, `
		SELECT id, email, password, api_key
		FROM users
		WHERE email = $1
	`, params.Email).Scan(&user.ID, &user.Email, &user.Password, &user.APIKey)
	if err != nil {
		return nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "invalid credentials",
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password)); err != nil {
		return nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "invalid credentials",
		}
	}

	return &LoginResponse{APIKey: user.APIKey}, nil
}

//encore:api auth method=POST path=/regenerate-key
func RegenerateKey(ctx context.Context) (*RegenerateKeyResponse, error) {
	userID, ok := auth.UserID()
	if !ok {
		return nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "user not authenticated",
		}
	}

	newKey, err := generateAPIKey()
	if err != nil {
		return nil, &errs.Error{
			Code:    errs.Internal,
			Message: "failed to generate new key",
		}
	}

	_, err = db.Exec(ctx, `
		UPDATE users
		SET api_key = $1
		WHERE email = $2
	`, newKey, string(userID))
	if err != nil {
		return nil, &errs.Error{
			Code:    errs.Internal,
			Message: "failed to update key",
		}
	}

	return &RegenerateKeyResponse{NewAPIKey: newKey}, nil
}

//encore:authhandler
func AuthHandler(ctx context.Context, apiKey string) (auth.UID, error) {
	// Validate API key format
	if !strings.HasPrefix(apiKey, "esk_") || len(apiKey) < 8 {
		return "", &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "invalid API key format; must start with 'esk_'",
		}
	}

	// Check if API key exists in the database
	var user User
	err := db.QueryRow(ctx, `
		SELECT id, email, api_key
		FROM users
		WHERE api_key = $1
	`, apiKey).Scan(&user.ID, &user.Email, &user.APIKey)
	if err != nil {
		return "", &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "invalid API key",
		}
	}

	// Return user ID as the authenticated UID
	return auth.UID(user.Email), nil
}

// ProtectedParams for the secure endpoint
type ProtectedParams struct {
	Data string `json:"data"`
}

// ProtectedResponse from the secure endpoint
type ProtectedResponse struct {
	Message string `json:"message"`
}

//encore:api auth method=POST path=/protected
func Protected(ctx context.Context, params *ProtectedParams) (*ProtectedResponse, error) {
	if params.Data == "" {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "data is required",
		}
	}

	// Get authenticated user ID (email in this case)
	userID, ok := auth.UserID()
	if !ok {
		return nil, &errs.Error{
			Code:    errs.Unauthenticated,
			Message: "user not authenticated",
		}
	}
	return &ProtectedResponse{Message: "Protected data for " + string(userID) + ": " + params.Data}, nil
}
