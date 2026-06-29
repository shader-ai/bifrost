// Package confidentiality implements the URAI confidentiality detection engine in Go.
// It is a port of backend/recording/confidentiality_pipeline.py and related modules.
package confidentiality

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

// Canonical category labels are pinned in resource/confidentiality_category_labels.json
// (repo root). Keep confidentiality/category_labels.json in sync with that file.
//
//go:embed category_labels.json
var categoryLabelsJSON []byte

// CanonicalCategoryLabels returns the pinned top-level category vocabulary.
func CanonicalCategoryLabels() []string {
	var labels []string
	if err := json.Unmarshal(categoryLabelsJSON, &labels); err != nil {
		return nil
	}
	return labels
}

// CategorySeverityLevels maps canonical category names to their severity.
// Keys must match resource/confidentiality_category_labels.json (see CanonicalCategoryLabels).
var CategorySeverityLevels = map[string]string{
	"Secrets & Credentials":      "Critical",
	"PII (Personal)":             "High",
	"PHI (Health)":               "High",
	"PCI (Financial)":            "High",
	"Authentication Data":        "Critical",
	"Biometric Data":             "High",
	"Intellectual Property":      "Medium/High",
	"Legal & Compliance":         "High",
	"Internal Business":          "Medium",
	"HR & Employee Data":         "High",
	"Customer Data":              "High",
	"Security & Infrastructure":  "High",
	"Cloud & DevOps":             "Critical",
	"Communication Data":         "Medium/High",
	"Research & Confidential":    "Medium/High",
	"Educational Records":        "Medium/High",
	"Geolocation Data":           "Medium",
	"Behavioral Data":            "Medium",
	"Media & Sensitive Content":  "High",
	"Public/General":             "Low",
}

// categoryAliases maps lowercased aliases → canonical category names.
// Verbatim from _CATEGORY_ALIASES in confidentiality_pipeline.py.
var categoryAliases = map[string]string{
	"secrets":                "Secrets & Credentials",
	"secrets & credentials":  "Secrets & Credentials",
	"credential":             "Secrets & Credentials",
	"credentials":            "Secrets & Credentials",
	"pii":                    "PII (Personal)",
	"personal":               "PII (Personal)",
	"personal data":          "PII (Personal)",
	"phi":                    "PHI (Health)",
	"health":                 "PHI (Health)",
	"health data":            "PHI (Health)",
	"pci":                    "PCI (Financial)",
	"financial":              "PCI (Financial)",
	"payment":                "PCI (Financial)",
	"authentication":         "Authentication Data",
	"auth":                   "Authentication Data",
	"biometric":              "Biometric Data",
	"ip":                     "Intellectual Property",
	"intellectual property":  "Intellectual Property",
	"legal":                  "Legal & Compliance",
	"compliance":             "Legal & Compliance",
	"internal":               "Internal Business",
	"hr":                     "HR & Employee Data",
	"employee":               "HR & Employee Data",
	"customer":               "Customer Data",
	"security":               "Security & Infrastructure",
	"infrastructure":         "Security & Infrastructure",
	"devops":                 "Cloud & DevOps",
	"cloud":                  "Cloud & DevOps",
	"communication":          "Communication Data",
	"research":               "Research & Confidential",
	"education":              "Educational Records",
	"educational":            "Educational Records",
	"geolocation":            "Geolocation Data",
	"location":               "Geolocation Data",
	"behavioral":             "Behavioral Data",
	"media":                  "Media & Sensitive Content",
	"sensitive content":      "Media & Sensitive Content",
	"public":                 "Public/General",
	"general":                "Public/General",
}

// entityTypeCategoryMap maps normalized entity type codes → category names.
// Verbatim from _ENTITY_TYPE_CATEGORY_MAP in confidentiality_pipeline.py.
var entityTypeCategoryMap = map[string]string{
	"API_KEY":        "Secrets & Credentials",
	"PASSWORD":       "Secrets & Credentials",
	"CREDENTIALS":    "Secrets & Credentials",
	"SSH_KEY":        "Secrets & Credentials",
	"JWT":            "Secrets & Credentials",
	"ACCESS_TOKEN":   "Secrets & Credentials",
	"TOKEN":          "Secrets & Credentials",
	"DATE_OF_BIRTH":  "PII (Personal)",
	"DOB":            "PII (Personal)",
	"BIRTH_DATE":     "PII (Personal)",
	"EMAIL_ADDRESS":  "PII (Personal)",
	"PHONE_NUMBER":   "PII (Personal)",
	"PERSON":         "PII (Personal)",
	"PERSON_NAME":    "PII (Personal)",
	"US_SSN":         "PII (Personal)",
	"AADHAAR":        "PII (Personal)",
	"PAN":            "PII (Personal)",
	"PASSPORT":       "PII (Personal)",
	"DRIVER_LICENSE": "PII (Personal)",
	"CREDIT_CARD":    "PCI (Financial)",
	"CVV":            "PCI (Financial)",
	"IBAN_CODE":      "PCI (Financial)",
	"SWIFT_CODE":     "PCI (Financial)",
	"UPI_ID":         "PCI (Financial)",
	"ACCOUNT":        "PCI (Financial)",
	"OTP":            "Authentication Data",
	"MFA_CODE":       "Authentication Data",
	"SESSION_COOKIE": "Authentication Data",
	"IP_ADDRESS":     "Geolocation Data",
}

// birthContextPattern matches near-token text indicating a birth date context.
var birthContextPattern = regexp.MustCompile(`(?i)\b(dob|d\.?o\.?b\.?|date\s+of\s+birth|born\s+(on|in)?|birth\s*date|birthday|bday)\b`)

// textPatterns is a list of (pattern, category) pairs for entity text scanning.
// Verbatim from _TEXT_PATTERNS in confidentiality_pipeline.py.
var textPatterns = []struct {
	re       *regexp.Regexp
	category string
}{
	{regexp.MustCompile(`(?i)\b(mfa|otp|session cookie|authenticator)\b`), "Authentication Data"},
	{regexp.MustCompile(`(?i)\b(kubernetes|terraform|\.env|ci/cd|deployment config)\b`), "Cloud & DevOps"},
	{regexp.MustCompile(`(?i)\b(network diagram|firewall|vpn|incident report|server config)\b`), "Security & Infrastructure"},
	{regexp.MustCompile(`(?i)\b(contract|nda|audit report|compliance evidence|legal)\b`), "Legal & Compliance"},
	{regexp.MustCompile(`(?i)\b(patient|medical|prescription|diagnosis|insurance id|lab result)\b`), "PHI (Health)"},
	{regexp.MustCompile(`(?i)\b(payroll|employee id|offer letter|background check)\b`), "HR & Employee Data"},
	{regexp.MustCompile(`(?i)\b(source code|algorithm|ml model|design document|cad)\b`), "Intellectual Property"},
	{regexp.MustCompile(`(?i)\b(email|chat|slack|call transcript|meeting)\b`), "Communication Data"},
}

// CanonicalCategory maps a tokenizer-returned entity dict to its canonical category.
// Mirrors _canonical_category() in confidentiality_pipeline.py.
func CanonicalCategory(token map[string]interface{}, fullText string) string {
	// 1. Direct category alias lookup (lowercased).
	rawCategory := strings.ToLower(strings.TrimSpace(strVal(token, "category")))
	if cat, ok := categoryAliases[rawCategory]; ok {
		return cat
	}

	// 2. Entity type map (uppercase, - → _, strip leading I_).
	entityType := strings.ToLower(strings.TrimSpace(strVal(token, "entity_type")))
	entityKey := strings.ToUpper(strings.ReplaceAll(entityType, "-", "_"))
	if strings.HasPrefix(entityKey, "I_") {
		entityKey = entityKey[2:]
	}
	if cat, ok := entityTypeCategoryMap[entityKey]; ok {
		return cat
	}

	// 3. Birth-date context.
	if entityKey == "DATE" || entityKey == "DATE_TIME" {
		if looksLikeBirthDateInContext(fullText, token) {
			return "PII (Personal)"
		}
	}

	// 4. Token text scan.
	tokenText := strVal(token, "text")
	for _, p := range textPatterns {
		if p.re.MatchString(tokenText) {
			return p.category
		}
	}

	return "Public/General"
}

// HighestSeverity returns the most severe level in a list of category entries.
// Mirrors _highest_severity() in confidentiality_pipeline.py.
func HighestSeverity(cats []map[string]interface{}) string {
	levels := map[string]bool{}
	for _, c := range cats {
		if sl, ok := c["severity_level"].(string); ok {
			levels[sl] = true
		}
	}
	for _, level := range []string{"Critical", "High", "Medium/High", "Medium"} {
		if levels[level] {
			return level
		}
	}
	return "Low"
}

// looksLikeBirthDateInContext returns true when a DATE/DATE_TIME token appears
// near birth-related wording in the surrounding text (±64 chars).
func looksLikeBirthDateInContext(fullText string, token map[string]interface{}) bool {
	start := intVal(token, "start")
	end := intVal(token, "end")
	if start < 0 || end <= start || end > len(fullText) {
		return false
	}
	lo := start - 64
	if lo < 0 {
		lo = 0
	}
	hi := end + 64
	if hi > len(fullText) {
		hi = len(fullText)
	}
	return birthContextPattern.MatchString(fullText[lo:hi])
}

// strVal safely extracts a string from a JSON-derived map.
func strVal(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

// intVal safely extracts an int from a JSON-derived map (float64 from JSON).
func intVal(m map[string]interface{}, key string) int {
	if m == nil {
		return -1
	}
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return -1
}
