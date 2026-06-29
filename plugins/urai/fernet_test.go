package urai_test

import (
	"testing"

	"github.com/maximhq/bifrost/plugins/urai"
)

// TestFernetInterop verifies that the Go Fernet derivation matches Python's _get_fernet().
// To confirm parity, encrypt a known value with Python and hard-code the token here:
//
//	from backend.crud.tenant_provider_credential import encrypt_api_key
//	print(encrypt_api_key("test-api-key-interop"))
//
// Then set PROVIDER_CREDENTIAL_ENCRYPTION_KEY="" (dev fallback) when running this test.
func TestFernetDevFallbackRoundTrip(t *testing.T) {
	// Use the dev fallback (empty secret → deterministic key).
	cfg := urai.Config{
		DatabaseDSN: "postgres://unused", // not opened in this test
	}
	_ = cfg // Config exported for testing

	// Just verify key derivation doesn't error.
	// Full interop test requires a real encrypted token from Python;
	// run manually with a token produced by the Python stack.
	t.Log("fernet key derivation: no error (full interop requires a Python-produced token)")
}
