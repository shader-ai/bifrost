package urai

import (
	"fmt"
	"strings"
)

// providerModelPrefixes maps URAI provider codes to canonical upstream prefixes.
// Mirrors PROVIDER_MODEL_PREFIXES in gateway_runtime_service.py.
var providerModelPrefixes = map[string]string{
	"openai":    "openai",
	"anthropic": "anthropic",
	"xai":       "xai",
	"google":    "gemini",
	"azure":     "azure",
	"aws":       "aws",
	"cohere":    "cohere",
	"mistral":   "mistral",
}

// canonicalizeModel rewrites a model string to "upstream_prefix/model_code" form,
// matching Python's _canonicalize_model_id_for_upstream.
func canonicalizeModel(upstreamProvider string, model string) string {
	upstream := strings.ToLower(strings.TrimSpace(upstreamProvider))
	if upstream == "" {
		upstream = "openai"
	}

	// Strip any existing provider prefix before appending the canonical one.
	stripped := stripProviderPrefix(model)
	return fmt.Sprintf("%s/%s", upstream, stripped)
}

// stripProviderPrefix removes a known "provider/" prefix from a model string.
func stripProviderPrefix(model string) string {
	lowered := strings.ToLower(model)
	for prefix := range providerModelPrefixes {
		pfx := prefix + "/"
		if strings.HasPrefix(lowered, pfx) {
			return model[len(pfx):]
		}
	}
	// also strip "gemini/" (the canonical upstream for google)
	if strings.HasPrefix(lowered, "gemini/") {
		return model[7:]
	}
	return model
}
