package confidentiality

import (
	"encoding/json"
	"strings"
)

type llmInputMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// flattenLLMInputJSON turns stored llm_input JSON into plain text for detection.
func flattenLLMInputJSON(llmInputJSON string) string {
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

// textForDetection prefers full llm_input, then user-role prompt fallback.
func textForDetection(llmInput, prompt *string) string {
	if llmInput != nil {
		if t := flattenLLMInputJSON(*llmInput); t != "" {
			return t
		}
	}
	if prompt != nil {
		return strings.TrimSpace(*prompt)
	}
	return ""
}
