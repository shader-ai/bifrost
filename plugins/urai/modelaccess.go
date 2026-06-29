package urai

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// modelAccessResult holds resolved model metadata used for access checking and logging.
type modelAccessResult struct {
	ProviderModelID uuid.UUID
	ModelCode       string
	IsBlocked       bool
	NotFound        bool // true if no matching llm_provider_model row exists
}

// checkModelAccess resolves the llm_provider_model row and then checks the
// tenant_llm_model_access blocklist. Matches the Python logic in
// gateway_runtime_service.py (check_model_access).
//
// Returns (result, nil) on success.
// Returns (nil, err) with a 400-style error if the model is unknown.
// Returns (result{IsBlocked:true}, nil) if the model is in the blocklist.
func checkModelAccess(
	ctx context.Context,
	db *gorm.DB,
	tenantID string,
	providerID uuid.UUID,
	modelCode string,
) (*modelAccessResult, error) {
	today := time.Now().UTC()

	// Find the active provider model row within its validity window.
	var model dbLLMProviderModel
	err := db.WithContext(ctx).
		Where(
			"provider_id = ? AND model_code = ? AND is_active = true AND valid_from <= ? AND (valid_until IS NULL OR valid_until >= ?)",
			providerID, modelCode, today, today,
		).
		First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return &modelAccessResult{NotFound: true}, fmt.Errorf("urai: model %q not found in catalog (400)", modelCode)
		}
		return nil, fmt.Errorf("urai: model catalog lookup: %w", err)
	}

	result := &modelAccessResult{
		ProviderModelID: model.ID,
		ModelCode:       model.ModelCode,
	}

	// Row present in tenant_llm_model_access → blocked (403).
	var access dbTenantLLMModelAccess
	err = db.WithContext(ctx).
		Where("tenant_id = ? AND provider_model_id = ?", tenantID, model.ID).
		First(&access).Error
	if err == nil {
		result.IsBlocked = true
		return result, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("urai: model access check: %w", err)
	}
	return result, nil
}
