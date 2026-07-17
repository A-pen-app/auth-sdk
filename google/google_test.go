package google

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// signed builds an id_token-shaped JWT. profileClaims parses without verifying,
// so the key here is irrelevant to what is under test.
func signed(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestProfileClaims(t *testing.T) {
	t.Run("takes name and picture from the id_token", func(t *testing.T) {
		token := signed(t, jwt.MapClaims{
			"sub":     "gid-123",
			"email":   "a@b.com",
			"name":    "王小明",
			"picture": "https://lh3.googleusercontent.com/p.png",
		})
		name, photoURL := profileClaims(token)
		if name != "王小明" {
			t.Errorf("name = %q, want 王小明", name)
		}
		if photoURL != "https://lh3.googleusercontent.com/p.png" {
			t.Errorf("photoURL = %q", photoURL)
		}
	})

	t.Run("claims absent → empty strings", func(t *testing.T) {
		// LINE/Apple-style tokens may carry no profile at all.
		name, photoURL := profileClaims(signed(t, jwt.MapClaims{"sub": "gid-123"}))
		if name != "" || photoURL != "" {
			t.Errorf("want empty, got name=%q photoURL=%q", name, photoURL)
		}
	})

	t.Run("claims of the wrong type → empty strings, no panic", func(t *testing.T) {
		name, photoURL := profileClaims(signed(t, jwt.MapClaims{"name": 42, "picture": true}))
		if name != "" || photoURL != "" {
			t.Errorf("want empty, got name=%q photoURL=%q", name, photoURL)
		}
	})

	t.Run("not a JWT → empty strings, no panic", func(t *testing.T) {
		name, photoURL := profileClaims("garbage")
		if name != "" || photoURL != "" {
			t.Errorf("want empty, got name=%q photoURL=%q", name, photoURL)
		}
	})
}
