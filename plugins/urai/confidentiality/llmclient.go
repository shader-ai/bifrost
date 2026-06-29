package confidentiality

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLMConfig holds provider configuration for the confidentiality LLM client.
type LLMConfig struct {
	// Provider is one of: "ollama", "openai", "openrouter", "grok".
	Provider string

	OllamaHost string

	OpenAIAPIKey  string
	OpenAIBaseURL string // default: https://api.openai.com/v1

	OpenRouterAPIKey  string
	OpenRouterBaseURL string // default: https://openrouter.ai/api

	GrokAPIKey  string
	GrokBaseURL string // default: https://api.x.ai/v1

	TimeoutSeconds float64 // default: 30
}

// LLMClient is a lightweight HTTP client for the confidentiality LLM providers.
// Mirrors AIClient in backend/llm_router/ai_client.py.
type LLMClient struct {
	cfg    LLMConfig
	client *http.Client
}

// NewLLMClient constructs a LLMClient with sensible defaults.
func NewLLMClient(cfg LLMConfig) *LLMClient {
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.OpenAIBaseURL == "" {
		cfg.OpenAIBaseURL = "https://api.openai.com/v1"
	}
	if cfg.OpenRouterBaseURL == "" {
		cfg.OpenRouterBaseURL = "https://openrouter.ai/api"
	}
	if cfg.GrokBaseURL == "" {
		cfg.GrokBaseURL = "https://api.x.ai/v1"
	}
	if cfg.OllamaHost == "" {
		cfg.OllamaHost = "http://localhost:11434"
	}
	return &LLMClient{
		cfg:    cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds * float64(time.Second))},
	}
}

// GenerateResponse calls the configured LLM provider and returns the content string.
// messages is a list of {"role": "...", "content": "..."} maps.
func (c *LLMClient) GenerateResponse(ctx context.Context, model string, messages []map[string]string) (string, error) {
	switch strings.ToLower(c.cfg.Provider) {
	case "ollama":
		return c.callOllama(ctx, model, messages)
	case "openai":
		return c.callOpenAI(ctx, c.cfg.OpenAIAPIKey, c.cfg.OpenAIBaseURL, model, messages)
	case "openrouter":
		return c.callOpenAI(ctx, c.cfg.OpenRouterAPIKey, c.cfg.OpenRouterBaseURL, model, messages)
	case "grok":
		return c.callOpenAI(ctx, c.cfg.GrokAPIKey, c.cfg.GrokBaseURL, model, messages)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", c.cfg.Provider)
	}
}

// callOllama uses Ollama's /api/generate endpoint (matching Python's ollama.Client.generate).
func (c *LLMClient) callOllama(ctx context.Context, model string, messages []map[string]string) (string, error) {
	// Use the last message content as the prompt (matches Python _call_ollama).
	prompt := ""
	if len(messages) > 0 {
		prompt = messages[len(messages)-1]["content"]
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.OllamaHost+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ollama: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		Response string `json:"response"`
		Message  struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("ollama: parse response: %w", err)
	}
	// prefer message.content (chat), fall back to response (generate)
	if result.Message.Content != "" {
		return result.Message.Content, nil
	}
	return result.Response, nil
}

// callOpenAI uses an OpenAI-compatible /v1/chat/completions endpoint.
// Works for OpenAI, OpenRouter, and Grok (all expose the same schema).
func (c *LLMClient) callOpenAI(ctx context.Context, apiKey, baseURL, model string, messages []map[string]string) (string, error) {
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	var msgs []msg
	for _, m := range messages {
		msgs = append(msgs, msg{Role: m["role"], Content: m["content"]})
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":    model,
		"messages": msgs,
	})

	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("openai-compat: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai-compat: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("openai-compat: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("openai-compat: HTTP %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("openai-compat: parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai-compat: empty choices in response")
	}
	return result.Choices[0].Message.Content, nil
}
