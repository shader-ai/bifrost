package confidentiality

import (
	"testing"
)

func TestCanonicalCategoryLabelsMatchSeverityMap(t *testing.T) {
	labels := CanonicalCategoryLabels()
	if len(labels) == 0 {
		t.Fatal("expected embedded category_labels.json to parse")
	}
	for _, label := range labels {
		if _, ok := CategorySeverityLevels[label]; !ok {
			t.Errorf("label %q missing from CategorySeverityLevels", label)
		}
	}
	for label := range CategorySeverityLevels {
		found := false
		for _, l := range labels {
			if l == label {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CategorySeverityLevels key %q missing from category_labels.json", label)
		}
	}
}

func TestReplaceCategoriesPersistsRows(t *testing.T) {
	db := openTestDB(t)
	rowID := mustInsertGatewayLogRow(t, db, "tenant-1", "patient diagnosis for John Doe")

	result := map[string]interface{}{
		"is_confidential": true,
		"detected_categories": []interface{}{
			map[string]interface{}{
				"category":        "PHI (Health)",
				"severity_level":  "High",
				"count":           2,
			},
			map[string]interface{}{
				"category":        "PII (Personal)",
				"severity_level":  "High",
				"count":           1,
			},
		},
	}
	if err := replaceCategories(db, rowID, "tenant-1", result); err != nil {
		t.Fatalf("replaceCategories: %v", err)
	}

	var rows []dbGatewayRequestCategoryRow
	if err := db.Where("gateway_request_log_id = ?", rowID).Find(&rows).Error; err != nil {
		t.Fatalf("query categories: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 category rows, got %d", len(rows))
	}
	byCat := map[string]dbGatewayRequestCategoryRow{}
	for _, r := range rows {
		byCat[r.Category] = r
	}
	if byCat["PHI (Health)"].EntityCount != 2 {
		t.Errorf("PHI count = %d, want 2", byCat["PHI (Health)"].EntityCount)
	}
	if byCat["PII (Personal)"].EntityCount != 1 {
		t.Errorf("PII count = %d, want 1", byCat["PII (Personal)"].EntityCount)
	}
}
