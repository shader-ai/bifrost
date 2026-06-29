package confidentiality

import (
	"context"
	"fmt"
	"strings"
)

// buildXMLPayload wraps system and user prompts in CDATA-safe XML.
// Mirrors build_confidentiality_detection_xml() + _cdata() in xml_prompting.py.
func buildXMLPayload(systemPrompt, userPrompt string) string {
	return "<system_prompt>" + cdata(systemPrompt) + "</system_prompt>" +
		"<user_prompt>" + cdata(userPrompt) + "</user_prompt>"
}

// cdata wraps text in a CDATA section, safely escaping any embedded "]]>".
func cdata(text string) string {
	escaped := strings.ReplaceAll(text, "]]>", "]]]]><![CDATA[>")
	return "<![CDATA[" + escaped + "]]>"
}

// errorResult returns a benign result dict for error conditions.
func errorResult() map[string]interface{} {
	return map[string]interface{}{
		"is_confidential":   false,
		"confidence_score":  0.0,
		"document_category": "Error",
		"reasoning":         "Error in analysis",
	}
}

// DetectConfidentiality runs confidentiality classification on a text chunk.
// Mirrors detect_confidentiality_gemma/phi/mistral() in confidentiality_detector.py
// (all three share the same logic; they differ only in model name passed to the LLM).
func DetectConfidentiality(ctx context.Context, client *LLMClient, model, prompt, text string) (map[string]interface{}, error) {
	if text == "" {
		return map[string]interface{}{
			"is_confidential":   false,
			"confidence_score":  0.0,
			"document_category": "N/A",
			"reasoning":         "empty_text",
		}, nil
	}

	xmlPayload := buildXMLPayload(prompt, text)
	content, err := client.GenerateResponse(ctx, model, []map[string]string{
		{"role": "user", "content": xmlPayload},
	})
	if err != nil {
		return errorResult(), fmt.Errorf("detect_confidentiality: LLM call: %w", err)
	}

	parsed := ParseFullResponse(strings.TrimSpace(content))
	if parsed == nil {
		return errorResult(), nil
	}

	m, ok := parsed.(map[string]interface{})
	if !ok {
		return errorResult(), nil
	}
	return m, nil
}
