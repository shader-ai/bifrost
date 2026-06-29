package urai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// requestAuthCtx holds the auth metadata stashed on the BifrostContext between pre/post hooks.
type requestAuthCtx struct {
	TenantID      string
	APIKeyID      uuid.UUID
	ConsumerID    *uuid.UUID
	ConsumerType  *string
}

// extractBearerToken returns the raw token from an "Authorization: Bearer <token>" header.
func extractBearerToken(authHeader string) (string, error) {
	trimmed := strings.TrimSpace(authHeader)
	if !strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		return "", fmt.Errorf("urai: missing Bearer token in Authorization header")
	}
	token := strings.TrimSpace(trimmed[7:])
	if token == "" {
		return "", fmt.Errorf("urai: empty Bearer token")
	}
	return token, nil
}

// hashToken computes the SHA-256 hex digest of the token (matches Python's key_hash).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// authenticateGatewayKey looks up the API key by hash, validates its status and
// expiry, and returns the auth context. It also fires a best-effort last_used_at update.
func authenticateGatewayKey(ctx context.Context, db *gorm.DB, token string) (*requestAuthCtx, error) {
	hash := hashToken(token)

	var row dbGatewayAPIKey
	if err := db.WithContext(ctx).
		Where("key_hash = ? AND status = 'active'", hash).
		First(&row).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("urai: invalid or revoked API key")
		}
		return nil, fmt.Errorf("urai: DB lookup for API key: %w", err)
	}

	if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("urai: API key has expired")
	}

	// best-effort last_used_at update (separate transaction, ignore errors)
	go func() {
		_ = db.Model(&dbGatewayAPIKey{}).
			Where("id = ?", row.ID).
			Update("last_used_at", time.Now().UTC()).Error
	}()

	auth := &requestAuthCtx{
		TenantID: row.TenantID,
		APIKeyID: row.ID,
	}

	if row.ConsumerID != nil {
		var consumer dbGatewayConsumer
		if err := db.WithContext(ctx).
			Where("id = ?", *row.ConsumerID).
			First(&consumer).Error; err == nil {
			auth.ConsumerID = &consumer.ID
			auth.ConsumerType = &consumer.ConsumerType
		}
	}

	return auth, nil
}
