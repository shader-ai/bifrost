package confidentiality

import "regexp"

// High-confidence regex patterns that do not depend on the confidentiality LLM.
// Used as a fallback when the detector is unavailable and to catch structured
// secrets (e.g. payment card numbers) that classifiers may miss in long chats.
var patternScans = []struct {
	re       *regexp.Regexp
	category string
}{
	{regexp.MustCompile(`\b(?:\d{4}[\s-]?){3}\d{1,7}\b`), "PCI (Financial)"},
	{regexp.MustCompile(`(?i)\b[A-Z]{5}[0-9]{4}[A-Z]\b`), "PII (Personal)"}, // Indian PAN
	{regexp.MustCompile(`(?i)\b[\w.+-]+@[\w-]+\.[\w.-]+\b`), "PII (Personal)"},
	{regexp.MustCompile(`sk-[A-Za-z0-9]{16,}`), "Secrets & Credentials"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "Secrets & Credentials"},
	{regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----`), "Secrets & Credentials"},
}

// patternScanCategories returns detected_categories from regex matches on full text.
func patternScanCategories(text string) []map[string]interface{} {
	if text == "" {
		return nil
	}
	counts := map[string]int{}
	for _, scan := range patternScans {
		n := len(scan.re.FindAllString(text, -1))
		if n > 0 {
			counts[scan.category] += n
		}
	}
	if len(counts) == 0 {
		return nil
	}
	var out []map[string]interface{}
	for cat, count := range counts {
		out = append(out, map[string]interface{}{
			"category":       cat,
			"severity_level": CategorySeverityLevels[cat],
			"count":          count,
		})
	}
	return out
}

// mergePatternScan enriches a confidentiality result with regex-detected categories.
// When patterns match, marks the request confidential with high confidence.
func mergePatternScan(result map[string]interface{}, text string) map[string]interface{} {
	patternCats := patternScanCategories(text)
	if len(patternCats) == 0 {
		return result
	}
	if result == nil {
		result = map[string]interface{}{}
	}

	existing, _ := result["detected_categories"].([]interface{})
	merged := mergeCategoryLists(existing, patternCats)
	result["detected_categories"] = merged
	var allCats []map[string]interface{}
	for _, item := range merged {
		if m, ok := item.(map[string]interface{}); ok {
			allCats = append(allCats, m)
		}
	}
	result["highest_severity_level"] = HighestSeverity(allCats)
	result["is_confidential"] = true
	if floatVal(result, "confidence_score") < 0.95 {
		result["confidence_score"] = 0.95
	}
	reasoning, _ := result["reasoning"].(string)
	if reasoning == "" || reasoning == "detection_failed" {
		result["reasoning"] = "Pattern scan detected sensitive structured data (payment card, credentials, or secrets)."
	}
	return result
}

func mergeCategoryLists(existing []interface{}, patternCats []map[string]interface{}) []interface{} {
	counts := map[string]int{}
	severity := map[string]string{}
	for _, raw := range existing {
		cat, _ := raw.(map[string]interface{})
		if cat == nil {
			continue
		}
		name, _ := cat["category"].(string)
		if name == "" {
			continue
		}
		switch v := cat["count"].(type) {
		case int:
			counts[name] += v
		case float64:
			counts[name] += int(v)
		}
		if sl, _ := cat["severity_level"].(string); sl != "" {
			severity[name] = sl
		}
	}
	for _, cat := range patternCats {
		name, _ := cat["category"].(string)
		if name == "" {
			continue
		}
		switch v := cat["count"].(type) {
		case int:
			counts[name] += v
		case float64:
			counts[name] += int(v)
		}
		if sl, _ := cat["severity_level"].(string); sl != "" {
			severity[name] = sl
		}
	}
	var out []interface{}
	for name, count := range counts {
		entry := map[string]interface{}{
			"category": name,
			"count":    count,
		}
		if sl := severity[name]; sl != "" {
			entry["severity_level"] = sl
		}
		out = append(out, entry)
	}
	return out
}
