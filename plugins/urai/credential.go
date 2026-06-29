package urai

import (
	"context"
	"fmt"
	"strings"

	"github.com/fernet/fernet-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// resolvedCredential holds the decrypted provider key and provider metadata.
type resolvedCredential struct {
	ProviderName     string // e.g. "openai", "anthropic", "google"
	UpstreamProvider string // canonical upstream prefix (e.g. "gemini" for google)
	RawAPIKey        string
	ProviderModelID  *uuid.UUID // resolved model row ID, used for blocklist check
}

// inferProviderFromModel maps model string prefixes to URAI provider codes.
// Mirrors PROVIDER_MODEL_PREFIXES + prefix detection in gateway_runtime_service.py.
func inferProviderFromModel(model string) string {
	lowered := strings.ToLower(model)
	switch {
	case strings.HasPrefix(lowered, "openai/") || strings.HasPrefix(lowered, "gpt"):
		return "openai"
	case strings.HasPrefix(lowered, "anthropic/") || strings.HasPrefix(lowered, "claude"):
		return "anthropic"
	case strings.HasPrefix(lowered, "gemini/") || strings.HasPrefix(lowered, "google/"):
		return "google"
	case strings.HasPrefix(lowered, "azure/"):
		return "azure"
	case strings.HasPrefix(lowered, "xai/") || strings.HasPrefix(lowered, "grok"):
		return "xai"
	case strings.HasPrefix(lowered, "aws/") || strings.HasPrefix(lowered, "bedrock/"):
		return "aws"
	case strings.HasPrefix(lowered, "cohere/"):
		return "cohere"
	case strings.HasPrefix(lowered, "mistral/"):
		return "mistral"
	default:
		return ""
	}
}

// resolveProviderCredential looks up the active credential for the tenant+model,
// Fernet-decrypts it, and returns provider metadata.
func resolveProviderCredential(
	ctx context.Context,
	db *gorm.DB,
	fernetKey *fernet.Key,
	tenantID string,
	model string,
) (*resolvedCredential, error) {
	providerCode := inferProviderFromModel(model)

	var cred dbLLMProviderCredential
	var provider dbLLMProvider

	if providerCode != "" {
		// Find the provider row matching the inferred code for this tenant (or global)
		if err := db.WithContext(ctx).
			Where("(tenant_id = ? OR tenant_id IS NULL) AND code = ?", tenantID, providerCode).
			Order("tenant_id DESC NULLS LAST").
			First(&provider).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("urai: provider lookup (%s): %w", providerCode, err)
			}
			// fall through to single-active-credential path
		} else {
			// Found provider — look up active credential
			if err := db.WithContext(ctx).
				Where("tenant_id = ? AND provider_id = ? AND is_active = true", tenantID, provider.ID).
				First(&cred).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					return nil, fmt.Errorf("urai: credential lookup for provider %s: %w", providerCode, err)
				}
				// fall through to single-active-credential path
			} else {
				goto decrypt
			}
		}
	}

	// Single-active-credential fallback: pick the one active credential for the tenant
	{
		var creds []dbLLMProviderCredential
		if err := db.WithContext(ctx).
			Where("tenant_id = ? AND is_active = true", tenantID).
			Find(&creds).Error; err != nil {
			return nil, fmt.Errorf("urai: credential fallback lookup: %w", err)
		}
		if len(creds) != 1 {
			return nil, fmt.Errorf("urai: cannot infer provider from model %q and no single active credential", model)
		}
		cred = creds[0]
		if err := db.WithContext(ctx).
			Where("id = ?", cred.ProviderID).
			First(&provider).Error; err != nil {
			return nil, fmt.Errorf("urai: provider row for credential: %w", err)
		}
	}

decrypt:
	rawKey, err := fernetDecrypt(fernetKey, cred.EncryptedCredential)
	if err != nil {
		return nil, fmt.Errorf("urai: decrypt credential for tenant %s: %w", tenantID, err)
	}

	upstreamProvider := upstreamProviderFromMeta(provider)

	return &resolvedCredential{
		ProviderName:     provider.Code,
		UpstreamProvider: upstreamProvider,
		RawAPIKey:        rawKey,
	}, nil
}

// upstreamProviderFromMeta extracts the upstream_provider_code from provider metadata,
// falling back to PROVIDER_MODEL_PREFIXES, then provider.Code.
func upstreamProviderFromMeta(p dbLLMProvider) string {
	if p.MetadataJSON != nil {
		if upstream, ok := p.MetadataJSON["upstream_provider_code"].(string); ok && strings.TrimSpace(upstream) != "" {
			return strings.TrimSpace(strings.ToLower(upstream))
		}
	}
	if mapped, ok := providerModelPrefixes[p.Code]; ok {
		return mapped
	}
	return p.Code
}
