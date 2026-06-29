package urai

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

// suspectPattern holds a compiled regex plus metadata for a governance finding.
type suspectPattern struct {
	re          *regexp.Regexp
	findingType string
	severity    string
}

// suspectPatterns mirrors SUSPECT_PATTERNS in backend/governance/detector.py.
var suspectPatterns = []suspectPattern{
	{regexp.MustCompile(`sk-[A-Za-z0-9]{16,}`), "api_key_like_token", "high"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws_access_key_id", "high"},
	{regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----`), "private_key_block", "critical"},
}

// governanceWriter serialises JSONL writes with a mutex.
type governanceWriter struct {
	path string
	mu   sync.Mutex
}

func newGovernanceWriter(path string) *governanceWriter {
	return &governanceWriter{path: path}
}

type governanceFinding struct {
	Detector    string                 `json:"detector"`
	FindingType string                 `json:"finding_type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Details     map[string]interface{} `json:"details"`
}

type governanceRecord struct {
	CorrelationID    string              `json:"correlation_id"`
	TenantID         string              `json:"tenant_id"`
	Model            string              `json:"model"`
	Findings         []governanceFinding `json:"findings"`
	DetectorLatencyMS int64              `json:"detector_latency_ms"`
	StoredAt         string              `json:"stored_at"`
}

func (w *governanceWriter) append(rec governanceRecord) {
	rec.StoredAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return // fail open
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s\n", data)
}

// runGovernanceScan evaluates promptText against SUSPECT_PATTERNS and appends
// any findings to the governance JSONL file. It is always called in a goroutine
// and never blocks the request path.
func (p *UraiPlugin) runGovernanceScan(correlationID, tenantID, model, promptText string) {
	if p.governance == nil || promptText == "" {
		return
	}
	started := time.Now()
	var findings []governanceFinding
	for _, sp := range suspectPatterns {
		if sp.re.MatchString(promptText) {
			findings = append(findings, governanceFinding{
				Detector:    "pattern_scan",
				FindingType: sp.findingType,
				Severity:    sp.severity,
				Confidence:  0.95,
				Details:     map[string]interface{}{"note": "Potential secret-like content detected in prompt payload"},
			})
		}
	}
	if len(findings) == 0 {
		return
	}
	p.governance.append(governanceRecord{
		CorrelationID:    correlationID,
		TenantID:         tenantID,
		Model:            model,
		Findings:         findings,
		DetectorLatencyMS: time.Since(started).Milliseconds(),
	})
}
