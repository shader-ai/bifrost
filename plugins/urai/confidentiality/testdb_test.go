package confidentiality

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(`
		CREATE TABLE gateway_request_log (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			prompt TEXT
		);
		CREATE TABLE gateway_request_category (
			id TEXT PRIMARY KEY,
			gateway_request_log_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			category TEXT NOT NULL,
			severity_level TEXT,
			entity_count INTEGER NOT NULL DEFAULT 0
		);
	`).Error; err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func mustInsertGatewayLogRow(t *testing.T, db *gorm.DB, tenantID, prompt string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := db.Exec(
		"INSERT INTO gateway_request_log (id, tenant_id, prompt) VALUES (?, ?, ?)",
		id.String(), tenantID, prompt,
	).Error; err != nil {
		t.Fatalf("insert log row: %v", err)
	}
	return id
}
