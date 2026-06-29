package urai

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/fernet/fernet-go"
)

const fernetDevFallback = "urai-dev-only-not-for-production-000"

// newFernetKey derives a Fernet key from the configured secret.
// Matches Python's _get_fernet():
//
//	key_material = env or fallback
//	derived = sha256(key_material)
//	key = base64url(derived)
func newFernetKey(rawSecret string) (*fernet.Key, error) {
	if rawSecret == "" {
		rawSecret = fernetDevFallback
	}
	hash := sha256.Sum256([]byte(rawSecret))
	encoded := base64.URLEncoding.EncodeToString(hash[:])
	k, err := fernet.DecodeKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("urai: fernet key derivation failed: %w", err)
	}
	return k, nil
}

// fernetDecrypt decrypts a Fernet token with no TTL check (matches Python's
// fernet.decrypt without a max_age argument).
func fernetDecrypt(k *fernet.Key, ciphertext string) (string, error) {
	msg := fernet.VerifyAndDecrypt([]byte(ciphertext), 0, []*fernet.Key{k})
	if msg == nil {
		return "", fmt.Errorf("urai: fernet decrypt failed (wrong key or corrupted token)")
	}
	return string(msg), nil
}
