package confidentiality

import (
	"encoding/json"
	"regexp"
	"strings"
)

// reJSONArray matches the first JSON array in text.
var reJSONArray = regexp.MustCompile(`\[[\s\S]*?\]`)

// reJSONObject matches the first JSON object in text.
var reJSONObject = regexp.MustCompile(`\{[\s\S]*?\}`)

// reJSConcat strips JavaScript "+" string concatenation.
var reJSConcat = regexp.MustCompile(`"\s*\+\s*\n?\s*"`)

// ParseFullResponse extracts and parses the first JSON value (array or object) from
// free-form LLM output. Returns nil when no valid JSON is found.
// Mirrors parse_full_response() in backend/utils/json_utils.py.
func ParseFullResponse(rawText string) interface{} {
	arrayMatch := reJSONArray.FindString(rawText)
	objectMatch := reJSONObject.FindString(rawText)

	var candidate string
	if arrayMatch != "" {
		candidate = arrayMatch
	} else if objectMatch != "" {
		candidate = objectMatch
	}
	if candidate == "" {
		return nil
	}

	cleaned := reJSConcat.ReplaceAllString(candidate, `"`)
	var out interface{}
	if err := json.Unmarshal([]byte(cleaned), &out); err != nil {
		return nil
	}
	return out
}

// FindAndExtractEntity locates the first occurrence of searchText in fullText
// starting at startIndex and returns an entity dict with positional info.
// Returns nil if not found or parameters are invalid.
// Mirrors find_and_extract_entity() in backend/utils/json_utils.py.
func FindAndExtractEntity(fullText string, startIndex int, searchText string, entityType string) map[string]interface{} {
	if fullText == "" || searchText == "" || startIndex < 0 || startIndex >= len(fullText) {
		return nil
	}
	idx := strings.Index(fullText[startIndex:], searchText)
	if idx < 0 {
		return nil
	}
	abs := startIndex + idx
	return map[string]interface{}{
		"entity_type": entityType,
		"start":       abs,
		"end":         abs + len(searchText),
		"text":        searchText,
	}
}
