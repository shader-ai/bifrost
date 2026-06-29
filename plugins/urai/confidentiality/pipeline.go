package confidentiality

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Engine wraps the LLM clients and all configuration needed to run the
// confidentiality pipeline and persist results to the URAI database.
type Engine struct {
	Client          *LLMClient
	DetectorModel   string
	TokenizerModel  string
	DetectorPrompt  string
	TokenizerPrompt string
	Threshold       float64 // 0.8 default
	ChunkSize       int     // 6000 default
	ChunkOverlap    int     // 200 default
}

// ChunkText splits text into overlapping chunks for per-chunk detection.
// Mirrors chunk_text() in confidentiality_pipeline.py.
func (e *Engine) ChunkText(text string) []string {
	size := e.ChunkSize
	if size <= 0 {
		size = 6000
	}
	overlap := e.ChunkOverlap
	if overlap < 0 {
		overlap = 200
	}
	if text == "" {
		return nil
	}
	var chunks []string
	start := 0
	for start < len(text) {
		end := start + size
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, text[start:end])
		next := end - overlap
		if next <= start {
			break
		}
		start = next
	}
	return chunks
}

// MergeChunkResults merges per-chunk detect results into a single verdict.
// Mirrors merge_chunk_results() in confidentiality_pipeline.py.
func MergeChunkResults(results []map[string]interface{}) map[string]interface{} {
	if len(results) == 0 {
		return map[string]interface{}{
			"is_confidential":   false,
			"confidence_score":  0.0,
			"document_category": "N/A",
			"reasoning":         "no_chunks",
		}
	}

	isConfidential := false
	maxScore := 0.0
	var topResult map[string]interface{}

	for _, r := range results {
		if b, _ := r["is_confidential"].(bool); b {
			isConfidential = true
		}
		score := floatVal(r, "confidence_score")
		if score > maxScore {
			maxScore = score
			topResult = r
		}
	}
	if topResult == nil {
		topResult = results[0]
	}

	return map[string]interface{}{
		"is_confidential":   isConfidential,
		"confidence_score":  maxScore,
		"document_category": topResult["document_category"],
		"reasoning":         fmt.Sprintf("Analysed %d chunk(s). ", len(results)) + strings.TrimSpace(fmt.Sprint(topResult["reasoning"])),
	}
}

// ApplyThresholdFlag overwrites is_confidential based on confidence_score >= threshold.
// Mirrors _apply_threshold_flag() in confidentiality_pipeline.py.
func (e *Engine) ApplyThresholdFlag(result map[string]interface{}) bool {
	threshold := e.Threshold
	if threshold <= 0 {
		threshold = 0.8
	}
	rawConf := false
	if b, ok := result["is_confidential"].(bool); ok {
		rawConf = b
	}
	score := floatVal(result, "confidence_score")
	isConf := rawConf && score >= threshold
	result["is_confidential"] = isConf
	return isConf
}

// MergeSourceResults merges multiple per-source results (text + files) into one rollup.
// Mirrors _merge_results() / merge_source_results() in confidentiality_pipeline.py.
func MergeSourceResults(results []map[string]interface{}) map[string]interface{} {
	var real []map[string]interface{}
	for _, r := range results {
		if len(r) > 0 {
			real = append(real, r)
		}
	}
	if len(real) == 0 {
		return map[string]interface{}{
			"is_confidential":   false,
			"confidence_score":  0.0,
			"document_category": "N/A",
			"reasoning":         "no_results",
		}
	}

	isConfidential := false
	maxScore := 0.0
	var topResult map[string]interface{}

	for _, r := range real {
		if b, _ := r["is_confidential"].(bool); b {
			isConfidential = true
		}
		score := floatVal(r, "confidence_score")
		if score > maxScore {
			maxScore = score
			topResult = r
		}
	}
	if topResult == nil {
		topResult = real[0]
	}

	merged := map[string]interface{}{
		"is_confidential":   isConfidential,
		"confidence_score":  maxScore,
		"document_category": topResult["document_category"],
		"reasoning":         topResult["reasoning"],
	}

	// Union detected_categories (sum counts across sources).
	catCounts := map[string]int{}
	for _, src := range real {
		cats, _ := src["detected_categories"].([]interface{})
		for _, rawCat := range cats {
			cat, _ := rawCat.(map[string]interface{})
			if cat == nil {
				continue
			}
			name, _ := cat["category"].(string)
			if name == "" {
				continue
			}
			n := 0
			switch v := cat["count"].(type) {
			case int:
				n = v
			case float64:
				n = int(v)
			}
			catCounts[name] += n
		}
	}
	if len(catCounts) > 0 {
		type entry struct {
			name  string
			count int
		}
		var sorted []entry
		for name, count := range catCounts {
			sorted = append(sorted, entry{name, count})
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
		merged["detected_categories"] = detectedCats
		merged["highest_severity_level"] = highestSeverityFromList(detectedCats)
	}
	return merged
}

// AnalyzeText chunks text, runs detect per chunk, and merges.
// Mirrors analyze_text_confidentiality() in confidentiality_pipeline.py.
func (e *Engine) AnalyzeText(ctx context.Context, text string) (map[string]interface{}, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var chunkResults []map[string]interface{}
	for _, chunk := range e.ChunkText(text) {
		result, err := DetectConfidentiality(ctx, e.Client, e.DetectorModel, e.DetectorPrompt, chunk)
		if err != nil {
			// log-skip and continue — mirrors Python exception handling
			continue
		}
		chunkResults = append(chunkResults, result)
	}
	if len(chunkResults) == 0 {
		return nil, fmt.Errorf("all chunk detection calls failed")
	}
	return MergeChunkResults(chunkResults), nil
}

// -- DB types for writing results --

type dbGatewayRequestCategoryRow struct {
	ID                   uuid.UUID `gorm:"column:id"`
	GatewayRequestLogID  uuid.UUID `gorm:"column:gateway_request_log_id"`
	TenantID             string    `gorm:"column:tenant_id"`
	Category             string    `gorm:"column:category"`
	SeverityLevel        *string   `gorm:"column:severity_level"`
	EntityCount          int       `gorm:"column:entity_count"`
}

func (dbGatewayRequestCategoryRow) TableName() string { return "gateway_request_category" }

type dbGatewayRequestLogRow struct {
	ID                    uuid.UUID        `gorm:"column:id"`
	TenantID              string           `gorm:"column:tenant_id"`
	Prompt                *string          `gorm:"column:prompt"`
	ConfidentialityResult *json.RawMessage `gorm:"column:confidentiality_result;serializer:json"`
}

func (dbGatewayRequestLogRow) TableName() string { return "gateway_request_log" }

// AnalyzeGatewayRequest fetches the prompt from gateway_request_log, runs the
// full text confidentiality pipeline, and persists results to the DB.
// Called asynchronously after PostLLMHook commits the log row.
func (e *Engine) AnalyzeGatewayRequest(ctx context.Context, db *gorm.DB, rowID uuid.UUID) error {
	// Fetch the usage row.
	var row dbGatewayRequestLogRow
	if err := db.WithContext(ctx).
		Select("id, tenant_id, prompt").
		Where("id = ?", rowID).
		First(&row).Error; err != nil {
		return fmt.Errorf("confidentiality: fetch row %s: %w", rowID, err)
	}

	text := ""
	if row.Prompt != nil {
		text = strings.TrimSpace(*row.Prompt)
	}

	emptyResult := map[string]interface{}{
		"is_confidential":   false,
		"confidence_score":  0.0,
		"document_category": "N/A",
		"reasoning":         "empty_extracted_prompt",
	}

	var finalResult map[string]interface{}

	if text == "" {
		finalResult = emptyResult
	} else {
		textResult, err := e.AnalyzeText(ctx, text)
		if err != nil || textResult == nil {
			finalResult = emptyResult
		} else {
			isConf := e.ApplyThresholdFlag(textResult)
			if isConf {
				TokenizerSensitiveItemsAndEnrichResult(ctx, e.Client, e.TokenizerModel, e.TokenizerPrompt, text, textResult)
			}
			finalResult = textResult
		}
	}

	return e.persistResult(ctx, db, rowID, row.TenantID, finalResult)
}

// persistResult writes confidentiality_result to gateway_request_log and
// replaces category rows in gateway_request_category.
func (e *Engine) persistResult(ctx context.Context, db *gorm.DB, rowID uuid.UUID, tenantID string, result map[string]interface{}) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("confidentiality: marshal result: %w", err)
	}
	raw := json.RawMessage(resultJSON)

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&dbGatewayRequestLogRow{}).
			Where("id = ?", rowID).
			Update("confidentiality_result", raw).Error; err != nil {
			return fmt.Errorf("confidentiality: update log row: %w", err)
		}
		return replaceCategories(tx, rowID, tenantID, result)
	})
}

// replaceCategories implements the delete-then-insert pattern for gateway_request_category.
func replaceCategories(tx *gorm.DB, rowID uuid.UUID, tenantID string, result map[string]interface{}) error {
	if err := tx.Where("gateway_request_log_id = ?", rowID).
		Delete(&dbGatewayRequestCategoryRow{}).Error; err != nil {
		return fmt.Errorf("confidentiality: delete categories: %w", err)
	}

	rawCats, _ := result["detected_categories"].([]interface{})
	if len(rawCats) == 0 {
		return nil
	}

	type bucket struct {
		severity string
		count    int
	}
	seen := map[string]*bucket{}
	for _, raw := range rawCats {
		cat, _ := raw.(map[string]interface{})
		if cat == nil {
			continue
		}
		name, _ := cat["category"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		n := 0
		switch v := cat["count"].(type) {
		case int:
			n = v
		case float64:
			n = int(v)
		}
		sl, _ := cat["severity_level"].(string)
		if b, ok := seen[name]; ok {
			b.count += n
			if sl != "" {
				b.severity = sl
			}
		} else {
			seen[name] = &bucket{severity: sl, count: n}
		}
	}

	var rows []dbGatewayRequestCategoryRow
	for name, b := range seen {
		row := dbGatewayRequestCategoryRow{
			ID:                  uuid.New(),
			GatewayRequestLogID: rowID,
			TenantID:            tenantID,
			Category:            name,
			EntityCount:         b.count,
		}
		if b.severity != "" {
			sl := b.severity
			row.SeverityLevel = &sl
		}
		rows = append(rows, row)
	}
	if len(rows) > 0 {
		if err := tx.Create(&rows).Error; err != nil {
			return fmt.Errorf("confidentiality: insert categories: %w", err)
		}
	}
	return nil
}

// floatVal safely extracts a float64 from a JSON-derived map.
func floatVal(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	}
	return 0
}
