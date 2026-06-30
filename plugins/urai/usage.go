package urai

import (
	"encoding/json"
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
var usageNamespaceURL = uuid.MustParse("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

type llmInputMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// serializeLLMInput JSON-encodes the full chat messages[] sent to the gateway.
func serializeLLMInput(messages []schemas.ChatMessage) string {
	if len(messages) == 0 {
		return ""
	}
	out := make([]llmInputMessage, 0, len(messages))
	for _, msg := range messages {
		text := messageText(msg)
		role := strings.TrimSpace(string(msg.Role))
		if text == "" && role == "" {
			continue
		}
		out = append(out, llmInputMessage{Role: role, Content: text})
	}
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// messageText extracts plain text from a single chat message (any role).
func messageText(msg schemas.ChatMessage) string {
	if msg.Content == nil {
		return ""
	}
	if msg.Content.ContentStr != nil {
		return strings.TrimSpace(*msg.Content.ContentStr)
	}
	var parts []string
	for _, block := range msg.Content.ContentBlocks {
		if block.Type == schemas.ChatContentBlockTypeText && block.Text != nil && *block.Text != "" {
			parts = append(parts, *block.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// extractUserPrompt returns the latest user-role message text for this request turn.
// Full multi-turn history is stored separately in llm_input.
func extractUserPrompt(messages []schemas.ChatMessage) string {
	var last string
	for _, msg := range messages {
		if msg.Role != schemas.ChatMessageRoleUser {
			continue
		}
		if text := messageText(msg); text != "" {
			last = text
		}
	}
	return last
}

// extractLLMInputText flattens serialized llm_input JSON into text for confidentiality.
func extractLLMInputText(llmInputJSON string) string {
	raw := strings.TrimSpace(llmInputJSON)
	if raw == "" {
		return ""
	}
	var messages []llmInputMessage
	if err := json.Unmarshal([]byte(raw), &messages); err != nil {
		return ""
	}
	var parts []string
	for _, msg := range messages {
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			continue
		}
		role := strings.TrimSpace(msg.Role)
		if role != "" {
			parts = append(parts, "["+role+"]\n"+content)
		} else {
			parts = append(parts, content)
		}
	}
	return strings.Join(parts, "\n\n")
}

// textForConfidentialityDetection prefers full llm_input, then user-role prompt.
func textForConfidentialityDetection(llmInput, prompt *string) string {
	if llmInput != nil {
		if t := extractLLMInputText(*llmInput); t != "" {
			return t
		}
	}
	if prompt != nil {
		return strings.TrimSpace(*prompt)
	}
	return ""
}

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

// shouldRecordUsage returns true when PostLLMHook should insert gateway_request_log.
// Unary responses are recorded once; chunked streaming waits for the final chunk
// (StreamEndIndicator), matching bifrost RunPostLLMHooks streaming detection.
func shouldRecordUsage(ctx *schemas.BifrostContext, result *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) bool {
	requestType, _, _, _ := bifrost.GetResponseFields(result, bifrostErr)
	isStreaming := ctx.Value(schemas.BifrostContextKeyStreamStartTime) != nil && requestType != schemas.RealtimeRequest
	if !isStreaming {
		return true
	}
	return bifrost.IsFinalChunk(ctx)
}
