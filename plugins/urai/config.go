package urai

import (
	"os"
	"strconv"
)

// Config holds all configuration for the URAI plugin.
type Config struct {
	// DatabaseDSN is the PostgreSQL DSN for the URAI database.
	DatabaseDSN string

	// ProviderCredentialEncryptionKey is the raw secret used to derive the Fernet key.
	ProviderCredentialEncryptionKey string

	// InternalAPIBase is the base URL for URAI's Python internal endpoints.
	// Only used for fallback file resolution until Phase 5 is complete.
	// No trailing slash.
	InternalAPIBase string

	// BlockingConfidentialityEnabled enables the blocking pre-hook guardrail.
	// Off by default — matches current Python behaviour (detect-only async).
	BlockingConfidentialityEnabled bool

	// GovernanceFindingsPath is the file path for the governance findings JSONL.
	// Defaults to /var/log/urai/governance_findings.jsonl.
	GovernanceFindingsPath string

	// --- Confidentiality engine (Phase 3) ---

	// ConfidentialityEnabled controls whether the Go confidentiality engine runs.
	// Defaults to true; set URAI_GO_CONFIDENTIALITY=false to disable (kill-switch).
	ConfidentialityEnabled bool

	// AI_CLIENT: provider for the confidentiality LLMs ("ollama", "openai", "openrouter", "grok").
	AIClient string

	// OLLAMA_HOST: base URL for the Ollama API (default: http://localhost:11434).
	OllamaHost string

	// OPENAI_API_KEY / OPENAI_BASE_URL.
	OpenAIAPIKey  string
	OpenAIBaseURL string

	// OPENROUTER_API_KEY / OPENROUTER_BASE_URL.
	OpenRouterAPIKey  string
	OpenRouterBaseURL string

	// GROK_API_KEY / GROK_BASE_URL.
	GrokAPIKey  string
	GrokBaseURL string

	// CONFIDENTIAL_DETECTOR: model for confidentiality classification.
	ConfidentialDetectorModel string

	// CONFIDENTIAL_TOKENIZER: model for PII entity extraction.
	ConfidentialTokenizerModel string

	// CONFIDENTIAL_THRESHOLD: minimum confidence for is_confidential (default: 0.8).
	ConfidentialThreshold float64

	// CHUNK_SIZE / CHUNK_OVERLAP: text chunking parameters (defaults: 6000 / 200).
	ChunkSize    int
	ChunkOverlap int

	// DETECTOR_TIMEOUT_SECONDS: LLM call timeout (default: 30).
	DetectorTimeoutSeconds float64
}

// ConfigFromEnv builds a Config from environment variables.
func ConfigFromEnv() Config {
	threshold := 0.8
	if v := os.Getenv("CONFIDENTIAL_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = f
		}
	}
	chunkSize := 6000
	if v := os.Getenv("CHUNK_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			chunkSize = n
		}
	}
	chunkOverlap := 200
	if v := os.Getenv("CHUNK_OVERLAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			chunkOverlap = n
		}
	}
	timeout := 30.0
	if v := os.Getenv("DETECTOR_TIMEOUT_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			timeout = f
		}
	}

	return Config{
		DatabaseDSN:                     os.Getenv("DATABASE_URL"),
		ProviderCredentialEncryptionKey: os.Getenv("PROVIDER_CREDENTIAL_ENCRYPTION_KEY"),
		InternalAPIBase:                 getEnvOrDefault("URAI_INTERNAL_API_BASE", "http://localhost:8000"),
		BlockingConfidentialityEnabled:  os.Getenv("URAI_BLOCKING_CONFIDENTIALITY") == "true",
		GovernanceFindingsPath:          getEnvOrDefault("GOVERNANCE_FINDINGS_PATH", "/var/log/urai/governance_findings.jsonl"),

		ConfidentialityEnabled: os.Getenv("URAI_GO_CONFIDENTIALITY") != "false",

		AIClient:          getEnvOrDefault("AI_CLIENT", "ollama"),
		OllamaHost:        getEnvOrDefault("OLLAMA_HOST", "http://localhost:11434"),
		OpenAIAPIKey:      os.Getenv("OPENAI_API_KEY"),
		OpenAIBaseURL:     getEnvOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"),
		OpenRouterAPIKey:  os.Getenv("OPENROUTER_API_KEY"),
		OpenRouterBaseURL: getEnvOrDefault("OPENROUTER_BASE_URL", "https://openrouter.ai/api"),
		GrokAPIKey:        os.Getenv("GROK_API_KEY"),
		GrokBaseURL:       getEnvOrDefault("GROK_BASE_URL", "https://api.x.ai/v1"),

		ConfidentialDetectorModel:  getEnvOrDefault("CONFIDENTIAL_DETECTOR", "google/gemma-3-12b-it:free"),
		ConfidentialTokenizerModel: getEnvOrDefault("CONFIDENTIAL_TOKENIZER", "google/gemma-3-27b-it:free"),
		ConfidentialThreshold:      threshold,
		ChunkSize:                  chunkSize,
		ChunkOverlap:               chunkOverlap,
		DetectorTimeoutSeconds:     timeout,
	}
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
