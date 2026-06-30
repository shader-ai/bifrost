package urai

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openDB opens and configures a gorm DB pool to the URAI Postgres instance.
func openDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

// --- DB row structs (read-only; no GORM auto-migration) ---

type dbGatewayAPIKey struct {
	ID         uuid.UUID  `gorm:"column:id"`
	TenantID   string     `gorm:"column:tenant_id"`
	KeyHash    string     `gorm:"column:key_hash"`
	Status     string     `gorm:"column:status"`
	ConsumerID *uuid.UUID `gorm:"column:consumer_id"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
}

func (dbGatewayAPIKey) TableName() string { return "gateway_api_key" }

type dbGatewayConsumer struct {
	ID           uuid.UUID `gorm:"column:id"`
	TenantID     string    `gorm:"column:tenant_id"`
	ConsumerType string    `gorm:"column:consumer_type"`
}

func (dbGatewayConsumer) TableName() string { return "gateway_consumer" }

type dbLLMProvider struct {
	ID           uuid.UUID              `gorm:"column:id"`
	Code         string                 `gorm:"column:code"`
	TenantID     *string                `gorm:"column:tenant_id"`
	MetadataJSON map[string]interface{} `gorm:"column:metadata;serializer:json"`
}

func (dbLLMProvider) TableName() string { return "llm_provider" }

type dbLLMProviderCredential struct {
	ID                   uuid.UUID `gorm:"column:id"`
	TenantID             string    `gorm:"column:tenant_id"`
	ProviderID           uuid.UUID `gorm:"column:provider_id"`
	EncryptedCredential  string    `gorm:"column:encrypted_credential"`
	IsActive             bool      `gorm:"column:is_active"`
}

func (dbLLMProviderCredential) TableName() string { return "llm_provider_credential" }

type dbLLMProviderModel struct {
	ID         uuid.UUID `gorm:"column:id"`
	ProviderID uuid.UUID `gorm:"column:provider_id"`
	ModelCode  string    `gorm:"column:model_code"`
	IsActive   bool      `gorm:"column:is_active"`
	ValidFrom  time.Time `gorm:"column:valid_from"`
	ValidUntil *time.Time `gorm:"column:valid_until"`
}

func (dbLLMProviderModel) TableName() string { return "llm_provider_model" }

type dbTenantLLMModelAccess struct {
	ID            uuid.UUID `gorm:"column:id"`
	TenantID      string    `gorm:"column:tenant_id"`
	ProviderModelID uuid.UUID `gorm:"column:provider_model_id"`
}

func (dbTenantLLMModelAccess) TableName() string { return "tenant_llm_model_access" }

// dbGatewayRequestLog is used for inserting usage rows.
type dbGatewayRequestLog struct {
	ID               uuid.UUID  `gorm:"column:id"`
	TenantID         string     `gorm:"column:tenant_id"`
	GatewayAPIKeyID  *uuid.UUID `gorm:"column:gateway_api_key_id"`
	TraceID          uuid.UUID  `gorm:"column:trace_id"`
	Provider         string     `gorm:"column:provider"`
	Model            string     `gorm:"column:model"`
	Endpoint         string     `gorm:"column:endpoint"`
	HTTPStatusCode   int        `gorm:"column:http_status_code"`
	LatencyMS        int64      `gorm:"column:latency_ms"`
	PromptTokens     *int       `gorm:"column:prompt_tokens"`
	CompletionTokens *int       `gorm:"column:completion_tokens"`
	TotalTokens      *int       `gorm:"column:total_tokens"`
	ConsumerID       *uuid.UUID `gorm:"column:consumer_id"`
	ConsumerType     *string    `gorm:"column:consumer_type"`
	ErrorType        *string    `gorm:"column:error_type"`
	ErrorMessage     *string    `gorm:"column:error_message"`
	Prompt           *string    `gorm:"column:prompt"`
	LLMInput         *string    `gorm:"column:llm_input"`
	RequestTimestamp time.Time  `gorm:"column:request_timestamp"`
}

func (dbGatewayRequestLog) TableName() string { return "gateway_request_log" }
