package urai

import (
	"strings"
	"time"

	"github.com/google/uuid"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// ctxKeyUsageStartTime is used to stash the request start time on the BifrostContext.
const ctxKeyUsageStartTime schemas.BifrostContextKey = "urai-request-start-time"

// usageNamespaceURL is the UUID v5 namespace used for trace_id derivation.
// Matches Python: uuid.uuid5(uuid.NAMESPACE_URL, correlation_id)
var usageNamespaceURL = uuid.MustParse("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

// scheduleDeferredUsageRow waits for deferred token usage from the provider (streaming)
// and then patches the gateway_request_log row by trace_id.
func scheduleDeferredUsageRow(
	ctx *schemas.BifrostContext,
	db *gorm.DB,
	traceID uuid.UUID,
	logger schemas.Logger,
) {
	deferredChan, ok := ctx.Value(schemas.BifrostContextKeyDeferredUsage).(<-chan *schemas.BifrostLLMUsage)
	if !ok || deferredChan == nil {
		return
	}
	go func() {
		usage, open := <-deferredChan
		if !open || usage == nil {
			return
		}
		pt := usage.PromptTokens
		ct := usage.CompletionTokens
		tt := usage.TotalTokens
		err := db.Model(&dbGatewayRequestLog{}).
			Where("trace_id = ?", traceID).
			Updates(map[string]interface{}{
				"prompt_tokens":     pt,
				"completion_tokens": ct,
				"total_tokens":      tt,
			}).Error
		if err != nil && logger != nil {
			logger.Warn("urai: deferred usage update for trace %s: %v", traceID, err)
		}
	}()
}

// extractUserPrompt joins user-role message text, matching Python's
// _gateway_user_prompt_from_payload.
func extractUserPrompt(messages []schemas.ChatMessage) string {
	var parts []string
	for _, msg := range messages {
		if msg.Role != schemas.ChatMessageRoleUser {
			continue
		}
		if msg.Content == nil {
			continue
		}
		if msg.Content.ContentStr != nil {
			parts = append(parts, *msg.Content.ContentStr)
		} else {
			for _, block := range msg.Content.ContentBlocks {
				if block.Type == schemas.ChatContentBlockTypeText && block.Text != nil && *block.Text != "" {
					parts = append(parts, *block.Text)
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

// getRequestStartTime retrieves the stashed start time from context, falling back to now.
func getRequestStartTime(ctx *schemas.BifrostContext) time.Time {
	if t, ok := ctx.Value(ctxKeyUsageStartTime).(time.Time); ok {
		return t
	}
	return time.Now().UTC()
}

// getCorrelationID returns a stable correlation/request ID from context.
func getCorrelationID(ctx *schemas.BifrostContext) string {
	if id, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string); ok && id != "" {
		return id
	}
	return uuid.New().String()
}

// isFinalChunk returns true when the context represents the last streaming chunk
// (or any non-streaming response).
func isFinalChunk(ctx *schemas.BifrostContext) bool {
	return bifrost.IsFinalChunk(ctx)
}
