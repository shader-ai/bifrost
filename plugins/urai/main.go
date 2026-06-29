// Package urai implements the URAI builtin plugin for Bifrost.
// It authenticates gateway API keys, resolves and injects provider credentials,
// enforces model access controls, records per-request usage to gateway_request_log,
// scans prompts for secrets (governance), and runs confidentiality detection.
package urai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/google/uuid"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/plugins/urai/confidentiality"
	"gorm.io/gorm"
)

const PluginName = "urai"

// ctxKeyAuthCtx stores the requestAuthCtx between PreLLMHook and PostLLMHook.
const ctxKeyAuthCtx schemas.BifrostContextKey = "urai-auth-ctx"

// ctxKeyUsageRowID stores the inserted usage row ID so confidentiality can reference it.
const ctxKeyUsageRowID schemas.BifrostContextKey = "urai-usage-row-id"

// ctxKeyExtractedPrompt stores the user-role prompt text stashed in PreLLMHook.
const ctxKeyExtractedPrompt schemas.BifrostContextKey = "urai-extracted-prompt"

// UraiPlugin implements schemas.BasePlugin + schemas.LLMPlugin + schemas.HTTPTransportPlugin.
type UraiPlugin struct {
	cfg       Config
	db        *gorm.DB
	fernetKey *fernet.Key
	logger    schemas.Logger

	governance          *governanceWriter
	confidentialityEng  *confidentiality.Engine

	wg          sync.WaitGroup
	cleanupOnce sync.Once
	ctx         context.Context
	cancel      context.CancelFunc
}

// Init creates and returns a UraiPlugin. Called by the Bifrost HTTP server during startup.
func Init(logger schemas.Logger) (*UraiPlugin, error) {
	cfg := ConfigFromEnv()
	return InitWithConfig(cfg, logger)
}

// InitWithConfig creates a UraiPlugin with an explicit Config (useful for testing).
func InitWithConfig(cfg Config, logger schemas.Logger) (*UraiPlugin, error) {
	if cfg.DatabaseDSN == "" {
		return nil, fmt.Errorf("urai: DATABASE_URL is required")
	}

	db, err := openDB(cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("urai: open DB: %w", err)
	}

	fernetKey, err := newFernetKey(cfg.ProviderCredentialEncryptionKey)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &UraiPlugin{
		cfg:       cfg,
		db:        db,
		fernetKey: fernetKey,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Governance JSONL writer (always active).
	if cfg.GovernanceFindingsPath != "" {
		p.governance = newGovernanceWriter(cfg.GovernanceFindingsPath)
	}

	// Go confidentiality engine (on by default; URAI_GO_CONFIDENTIALITY=false disables).
	if cfg.ConfidentialityEnabled {
		llmCfg := confidentiality.LLMConfig{
			Provider:          cfg.AIClient,
			OllamaHost:        cfg.OllamaHost,
			OpenAIAPIKey:      cfg.OpenAIAPIKey,
			OpenAIBaseURL:     cfg.OpenAIBaseURL,
			OpenRouterAPIKey:  cfg.OpenRouterAPIKey,
			OpenRouterBaseURL: cfg.OpenRouterBaseURL,
			GrokAPIKey:        cfg.GrokAPIKey,
			GrokBaseURL:       cfg.GrokBaseURL,
			TimeoutSeconds:    cfg.DetectorTimeoutSeconds,
		}
		p.confidentialityEng = &confidentiality.Engine{
			Client:          confidentiality.NewLLMClient(llmCfg),
			DetectorModel:   cfg.ConfidentialDetectorModel,
			TokenizerModel:  cfg.ConfidentialTokenizerModel,
			DetectorPrompt:  confidentiality.PromptDefault,
			TokenizerPrompt: confidentiality.TokenizerPromptDefault,
			Threshold:       cfg.ConfidentialThreshold,
			ChunkSize:       cfg.ChunkSize,
			ChunkOverlap:    cfg.ChunkOverlap,
		}
	}

	if logger != nil {
		logger.Info("urai plugin initialized (go_confidentiality=%v, governance_path=%s)",
			cfg.ConfidentialityEnabled, cfg.GovernanceFindingsPath)
	}
	return p, nil
}

func (p *UraiPlugin) GetName() string { return PluginName }

func (p *UraiPlugin) Cleanup() error {
	var cleanupErr error
	p.cleanupOnce.Do(func() {
		p.cancel()
		p.wg.Wait()
		if sqlDB, err := p.db.DB(); err == nil {
			cleanupErr = sqlDB.Close()
		}
	})
	return cleanupErr
}

// --- HTTPTransportPlugin ---

// HTTPTransportPreHook handles file_id resolution before the request body is
// parsed by Bifrost core. Skipped entirely when no file_id is present.
func (p *UraiPlugin) HTTPTransportPreHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	if req == nil || !hasFileID(req.Body) {
		return nil, nil
	}
	resolved, err := resolveFileReferences(p.cfg.InternalAPIBase, req.Body)
	if err != nil {
		return nil, fmt.Errorf("urai: file resolution: %w", err)
	}
	req.Body = resolved
	return nil, nil
}

// HTTPTransportPostHook is a no-op for this plugin.
func (p *UraiPlugin) HTTPTransportPostHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return nil
}

// --- LLMPlugin ---

// PreLLMHook authenticates the gateway key, resolves + injects the provider
// credential, enforces model access controls, and fires async governance scan.
func (p *UraiPlugin) PreLLMHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	// Stash request start time for latency computation in PostLLMHook.
	ctx.SetValue(ctxKeyUsageStartTime, time.Now().UTC())

	if req == nil {
		return req, nil, nil
	}

	// 1. Extract Bearer token from Authorization header.
	headers, _ := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)
	authHeader := caseInsensitiveGet(headers, "authorization")
	if authHeader == "" {
		return req, shortCircuit401("missing Authorization header"), nil
	}

	token, err := extractBearerToken(authHeader)
	if err != nil {
		return req, shortCircuit401(err.Error()), nil
	}

	// 2. Authenticate: hash lookup in gateway_api_key.
	auth, err := authenticateGatewayKey(p.ctx, p.db, token)
	if err != nil {
		return req, shortCircuit401(err.Error()), nil
	}
	ctx.SetValue(ctxKeyAuthCtx, auth)

	// 3. Determine request model.
	model := requestModel(req)
	if model == "" {
		return req, shortCircuit400("model is required"), nil
	}

	// 4. Resolve provider credential + Fernet decrypt.
	cred, err := resolveProviderCredential(p.ctx, p.db, p.fernetKey, auth.TenantID, model)
	if err != nil {
		return req, shortCircuit400(fmt.Sprintf("no active credential: %v", err)), nil
	}

	// 5. Resolve the model code (strip provider prefix) then check access.
	modelCode := stripProviderPrefix(model)
	var providerID uuid.UUID
	// Fetch the provider ID for the resolved credential.
	var provider dbLLMProvider
	if dbErr := p.db.WithContext(p.ctx).
		Where("code = ? AND (tenant_id = ? OR tenant_id IS NULL)", cred.ProviderName, auth.TenantID).
		Order("tenant_id DESC NULLS LAST").
		First(&provider).Error; dbErr == nil {
		providerID = provider.ID
	}

	if providerID != uuid.Nil {
		access, accessErr := checkModelAccess(p.ctx, p.db, auth.TenantID, providerID, modelCode)
		if accessErr != nil && access != nil && access.NotFound {
			return req, shortCircuit400(fmt.Sprintf("unknown model: %s", modelCode)), nil
		}
		if access != nil && access.IsBlocked {
			return req, shortCircuit403(fmt.Sprintf("model %s is not permitted for this tenant", modelCode)), nil
		}
	}

	// 6. Canonicalize model and inject provider key.
	canonical := canonicalizeModel(cred.UpstreamProvider, modelCode)
	setRequestModel(req, canonical)
	ctx.SetValue(schemas.BifrostContextKeyPassthroughProviderKey, cred.RawAPIKey)

	// 7. Stash extracted prompt for usage recording and governance.
	promptText := extractPromptForGovernance(req)
	if promptText != "" {
		ctx.SetValue(ctxKeyExtractedPrompt, promptText)
		if p.governance != nil {
			correlationID := getCorrelationID(ctx)
			go p.runGovernanceScan(correlationID, auth.TenantID, canonical, promptText)
		}
	}

	if p.logger != nil {
		p.logger.Debug("urai: authenticated tenant=%s key=%s model=%s→%s",
			auth.TenantID, auth.APIKeyID, model, canonical)
	}
	return req, nil, nil
}

// PostLLMHook writes the gateway_request_log row and triggers async confidentiality.
// For streaming responses it waits for the final chunk before writing.
func (p *UraiPlugin) PostLLMHook(ctx *schemas.BifrostContext, result *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	// Only record on final chunk (non-streaming or last streaming chunk).
	if !isFinalChunk(ctx) {
		return result, bifrostErr, nil
	}

	auth, ok := ctx.Value(ctxKeyAuthCtx).(*requestAuthCtx)
	if !ok || auth == nil {
		// Pre-hook didn't succeed (e.g. 401 short-circuit) — nothing to record.
		return result, bifrostErr, nil
	}

	startTime := getRequestStartTime(ctx)
	correlationID := getCorrelationID(ctx)

	// Build and insert the row.
	rowID := uuid.New()
	row := p.buildUsageRow(ctx, auth, result, bifrostErr, startTime, correlationID, rowID)

	if err := p.db.WithContext(p.ctx).Create(&row).Error; err != nil {
		if p.logger != nil {
			p.logger.Warn("urai: insert gateway_request_log: %v", err)
		}
		// Non-fatal — don't fail the request.
		return result, bifrostErr, nil
	}

	// Attempt to fill deferred streaming token usage.
	scheduleDeferredUsageRow(ctx, p.db, row.TraceID, p.logger)

	// Trigger confidentiality analysis (Go engine only — no Python fallback).
	if p.confidentialityEng != nil {
		p.triggerGoConfidentialityAsync(rowID)
	}

	return result, bifrostErr, nil
}

// triggerGoConfidentialityAsync runs the Go confidentiality engine in a goroutine.
func (p *UraiPlugin) triggerGoConfidentialityAsync(rowID uuid.UUID) {
	eng := p.confidentialityEng
	db := p.db
	logger := p.logger
	go func() {
		if err := eng.AnalyzeGatewayRequest(p.ctx, db, rowID); err != nil && logger != nil {
			logger.Warn("urai: go confidentiality failed for row %s: %v", rowID, err)
		}
	}()
}

// buildUsageRow constructs the dbGatewayRequestLog struct from context + response.
func (p *UraiPlugin) buildUsageRow(
	ctx *schemas.BifrostContext,
	auth *requestAuthCtx,
	result *schemas.BifrostResponse,
	bifrostErr *schemas.BifrostError,
	startTime time.Time,
	correlationID string,
	rowID uuid.UUID,
) dbGatewayRequestLog {
	now := time.Now().UTC()
	latencyMS := now.Sub(startTime).Milliseconds()
	if latencyMS < 0 {
		latencyMS = 0
	}

	traceID := uuid.NewSHA1(usageNamespaceURL, []byte(correlationID))

	statusCode := 200
	var errType, errMsg *string
	if bifrostErr != nil {
		statusCode = 500
		if bifrostErr.StatusCode != nil {
			statusCode = *bifrostErr.StatusCode
		}
		if bifrostErr.Error != nil {
			errMsg = &bifrostErr.Error.Message
			if bifrostErr.Error.Type != nil {
				errType = bifrostErr.Error.Type
			}
		}
	}

	var provider, model, endpoint string
	if result != nil {
		if ef := result.GetExtraFields(); ef != nil {
			provider = string(ef.Provider)
			model = ef.ResolvedModelUsed
			endpoint = string(ef.RequestType)
			if ef.Latency > 0 {
				latencyMS = ef.Latency
			}
		}
	}

	var promptTok, completionTok, totalTok *int
	if result != nil && result.ChatResponse != nil && result.ChatResponse.Usage != nil {
		u := result.ChatResponse.Usage
		pt := u.PromptTokens
		ct := u.CompletionTokens
		tt := u.TotalTokens
		promptTok = &pt
		completionTok = &ct
		totalTok = &tt
	}

	// Extract prompt text from the stashed context value (set in PreLLMHook).
	var promptStr *string
	if pt, ok := ctx.Value(ctxKeyExtractedPrompt).(string); ok && pt != "" {
		promptStr = &pt
	}

	apiKeyID := &auth.APIKeyID
	return dbGatewayRequestLog{
		ID:               rowID,
		TenantID:         auth.TenantID,
		GatewayAPIKeyID:  apiKeyID,
		TraceID:          traceID,
		Provider:         provider,
		Model:            model,
		Endpoint:         endpoint,
		HTTPStatusCode:   statusCode,
		LatencyMS:        latencyMS,
		PromptTokens:     promptTok,
		CompletionTokens: completionTok,
		TotalTokens:      totalTok,
		ConsumerID:       auth.ConsumerID,
		ConsumerType:     auth.ConsumerType,
		ErrorType:        errType,
		ErrorMessage:     errMsg,
		Prompt:           promptStr,
		RequestTimestamp: startTime.UTC(),
	}
}

// --- helpers ---

func shortCircuit401(msg string) *schemas.LLMPluginShortCircuit {
	return &schemas.LLMPluginShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode:     bifrost.Ptr(401),
			AllowFallbacks: bifrost.Ptr(false),
			Error:          &schemas.ErrorField{Message: msg},
		},
	}
}

func shortCircuit403(msg string) *schemas.LLMPluginShortCircuit {
	return &schemas.LLMPluginShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode:     bifrost.Ptr(403),
			AllowFallbacks: bifrost.Ptr(false),
			Error:          &schemas.ErrorField{Message: msg},
		},
	}
}

func shortCircuit400(msg string) *schemas.LLMPluginShortCircuit {
	return &schemas.LLMPluginShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode:     bifrost.Ptr(400),
			AllowFallbacks: bifrost.Ptr(false),
			Error:          &schemas.ErrorField{Message: msg},
		},
	}
}

// caseInsensitiveGet retrieves a value from a string map ignoring key case.
func caseInsensitiveGet(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	lower := strings.ToLower(key)
	for k, v := range m {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return ""
}

// requestModel returns the model from a BifrostRequest.
func requestModel(req *schemas.BifrostRequest) string {
	if req.ChatRequest != nil {
		return req.ChatRequest.Model
	}
	if req.ResponsesRequest != nil {
		return req.ResponsesRequest.Model
	}
	return ""
}

// setRequestModel rewrites the model on the request.
func setRequestModel(req *schemas.BifrostRequest, model string) {
	if req.ChatRequest != nil {
		req.ChatRequest.Model = model
	}
	if req.ResponsesRequest != nil {
		req.ResponsesRequest.Model = model
	}
}

// extractPromptForGovernance returns all user-role message text joined for governance scanning.
func extractPromptForGovernance(req *schemas.BifrostRequest) string {
	if req.ChatRequest != nil {
		return extractUserPrompt(req.ChatRequest.Input)
	}
	return ""
}
