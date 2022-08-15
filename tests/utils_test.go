package tests

import (
	"os"
	"testing"

	"github.com/mrinjamul/mrinjamul-auth/utils"
)

// TestGetEnv tests the GetEnv function
func TestGetEnv(t *testing.T) {
	testcases := []struct {
		key string
		val string
	}{
		{"APP_NAME", "mrinjamul-auth"},
		{"APP_ENV", "development"},
		{"APP_DEBUG", "true"},
		{"APP_PORT", "8080"},
		{"APP_URL", "http://localhost:8080"},
		{"APP_KEY", "some-random-key"},
		{"APP_CORS_ORIGIN", "http://localhost:8080"},
		{"APP_CORS_METHODS", "GET, PUT, POST, DELETE"},
		{"APP_CORS_HEADERS", "Content-Type, Authorization"},
		{"APP_CORS_MAX_AGE", "600"},
		{"APP_CORS_EXPOSE_HEADERS", "Content-Type, Authorization"},
		{"APP_CORS_ALLOW_ORIGIN", "true"},
	}

	for _, tc := range testcases {
		os.Setenv(tc.key, tc.val)
		if val := utils.GetEnv(tc.key); val != tc.val {
			t.Errorf("GetEnv(%s) = %s, want %s", tc.key, val, tc.val)
		}
	}
}

// TestParseToken tests the ParseToken function
func TestParseToken(t *testing.T) {
	testcases := []struct {
		authorization string
		expectedToken string
		expectedError error
	}{
		{"Bearer 12345", "12345", nil},
	}
	for _, tc := range testcases {
		token, _ := utils.ParseToken(tc.authorization)
		if token != tc.expectedToken {
			t.Errorf("ParseToken returned an incorrect value: %s", token)
		}
	}
}

// TestVerifyHash tests the VerifyHash function
func TestVerifyHash(t *testing.T) {
	testcases := []struct {
		password string
		hash     string
		expected bool
	}{
		{"password", "$2a$10$dGi8WhmTVHBG7cl37bo2ue/L.lr1dfnm/5DCwzHxWhgD0gqXyJZji", true},
	}
	for _, tc := range testcases {
		if utils.VerifyHash(tc.password, tc.hash) != tc.expected {
			t.Errorf("VerifyHash returned an incorrect value: %t", tc.expected)
		}
	}
}

// TestHashAndSalt tests the HashAndSalt function
func TestHashAndSalt(t *testing.T) {
	testcases := []struct {
		password string
		expected string
	}{
		{"password", "$2a$10$dGi8WhmTVHBG7cl37bo2ue/L.lr1dfnm/5DCwzHxWhgD0gqXyJZji"},
	}
	for _, tc := range testcases {
		hashedPassword, _ := utils.HashAndSalt(tc.password)
		if !utils.VerifyHash(tc.password, hashedPassword) {
			t.Errorf("HashAndSalt returned an incorrect value: %s", hashedPassword)
		}
	}
}

// TestIsRestrictedUser tests the IsRestrictedUser function
func TestIsRestrictedUser(t *testing.T) {
	testcases := []struct {
		username string
		expected bool
	}{
		{"admin", true},
		{"root", true},
		{"me", true},
		{"system", true},
		{"search", true},
		{"user", false},
	}
	for _, tc := range testcases {
		if utils.IsRestrictedUser(tc.username) != tc.expected {
			t.Errorf("IsRestrictedUser returned an incorrect value: %t", tc.expected)
		}
	}
}

// TestIsValidUserName tests the IsValidUserName function
func TestIsValidUserName(t *testing.T) {
	testcases := []struct {
		username string
		expected bool
	}{
		{"", false},
		{"mrinjamul", true},
	}
	for _, tc := range testcases {
		if utils.IsValidUserName(tc.username) != tc.expected {
			t.Errorf("IsValidUserName returned an incorrect value: %t", tc.expected)
		}
	}
}

// TestIsValidEmail tests the IsValidEmail function
func TestIsValidEmail(t *testing.T) {
}

// TestIsValidPassword tests the IsValidPassword function
func TestIsValidPassword(t *testing.T) {
	testcases := []struct {
		password string
		expected bool
	}{
		{"", false},
		{"Devil#123", true},
	}
	for _, tc := range testcases {
		if utils.IsValidPassword(tc.password) != tc.expected {
			t.Errorf("IsValidPassword returned an incorrect value: %t", tc.expected)
		}
	}
}
