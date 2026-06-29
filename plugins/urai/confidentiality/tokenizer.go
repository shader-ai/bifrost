package confidentiality

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// RunTokenizer calls the PII tokenizer LLM and returns a list of entity dicts.
// Mirrors confidential_tokenizer() / PIIAnalyzer.analyze_with_gemma/mistral() in tokenizer.py.
func RunTokenizer(ctx context.Context, client *LLMClient, model, tokenizerPrompt, text string) ([]map[string]interface{}, error) {
	if text == "" {
		return nil, nil
	}

	m := strings.ToLower(model)
	var messages []map[string]string
	if strings.Contains(m, "gemma") {
		// Gemma: both messages use "user" role (matches Python TODO comment).
		messages = []map[string]string{
			{"role": "user", "content": tokenizerPrompt},
			{"role": "user", "content": text},
		}
	} else {
		// Mistral / others: system + user.
		messages = []map[string]string{
			{"role": "system", "content": tokenizerPrompt},
			{"role": "user", "content": text},
		}
	}

	content, err := client.GenerateResponse(ctx, model, messages)
	if err != nil {
		return nil, fmt.Errorf("tokenizer: LLM call: %w", err)
	}

	parsed := ParseFullResponse(strings.TrimSpace(content))
	if parsed == nil {
		return nil, nil
	}

	rawList, ok := parsed.([]interface{})
	if !ok {
		return nil, nil
	}

	// Convert raw JSON list to []map[string]interface{}, find exact positions,
	// and attach categories — mirrors PIIAnalyzer.analyze_with_gemma.
	var results []map[string]interface{}
	startIndex := 0
	for _, raw := range rawList {
		entity, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		entityText := strVal(entity, "text")
		entityType := strVal(entity, "entity_type")
		found := FindAndExtractEntity(text, startIndex, entityText, entityType)
		if found == nil {
			continue
		}
		if cat := strVal(entity, "category"); cat != "" {
			found["category"] = cat
		}
		results = append(results, found)
		if end := intVal(found, "end"); end > startIndex {
			startIndex = end
		}
	}

	return results, nil
}

// TokenizerSensitiveItemsAndEnrichResult runs the tokenizer and enriches the
// confidentiality result dict with detected_categories + highest_severity_level.
// Returns the sensitive-item list (caller may discard for gateway path).
// Mirrors tokenizer_sensitive_items_and_enrich_result() in confidentiality_pipeline.py.
func TokenizerSensitiveItemsAndEnrichResult(
	ctx context.Context,
	client *LLMClient,
	model, tokenizerPrompt string,
	text string,
	result map[string]interface{},
) []map[string]interface{} {
	tokens, err := RunTokenizer(ctx, client, model, tokenizerPrompt, text)
	if err != nil || len(tokens) == 0 {
		return nil
	}

	confidenceScore := result["confidence_score"]
	categoryCounts := map[string]int{}
	var items []map[string]interface{}

	for _, token := range tokens {
		canonical := CanonicalCategory(token, text)
		categoryCounts[canonical]++
		items = append(items, map[string]interface{}{
			"entity_type":      strVal(token, "entity_type"),
			"category":         canonical,
			"sensitive_data":   strVal(token, "text"),
			"confidence_score": confidenceScore,
			"start":            intVal(token, "start"),
			"end":              intVal(token, "end"),
		})
	}

	// Build sorted detected_categories list.
	type catEntry struct {
		name  string
		count int
	}
	var sorted []catEntry
	for name, count := range categoryCounts {
		sorted = append(sorted, catEntry{name, count})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })

	var detectedCats []map[string]interface{}
	for _, e := range sorted {
		detectedCats = append(detectedCats, map[string]interface{}{
			"category":       e.name,
			"severity_level": CategorySeverityLevels[e.name],
			"count":          e.count,
		})
	}
	result["detected_categories"] = detectedCats
	result["highest_severity_level"] = highestSeverityFromList(detectedCats)
	delete(result, "highest_risk_level")

	return items
}

func highestSeverityFromList(cats []map[string]interface{}) string {
	for _, level := range []string{"Critical", "High", "Medium/High", "Medium"} {
		for _, c := range cats {
			if sl, _ := c["severity_level"].(string); sl == level {
				return level
			}
		}
	}
	return "Low"
}
