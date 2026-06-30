package confidentiality

import "testing"

func TestPatternScanCategories_creditCard(t *testing.T) {
	text := "My credit card number is 7373-7333-8383-8333, I had made a payment using this"
	cats := patternScanCategories(text)
	if len(cats) == 0 {
		t.Fatal("expected PCI category from credit card pattern")
	}
	if cats[0]["category"] != "PCI (Financial)" {
		t.Fatalf("category = %v, want PCI (Financial)", cats[0]["category"])
	}
}

func TestMergePatternScan_overridesDetectionFailed(t *testing.T) {
	text := "card 4111 1111 1111 1111"
	result := mergePatternScan(map[string]interface{}{
		"is_confidential":   false,
		"confidence_score":  0.0,
		"document_category": "N/A",
		"reasoning":         "detection_failed",
	}, text)
	if result["is_confidential"] != true {
		t.Fatalf("is_confidential = %v, want true", result["is_confidential"])
	}
	cats, _ := result["detected_categories"].([]interface{})
	if len(cats) == 0 {
		t.Fatal("expected detected_categories after pattern merge")
	}
}
