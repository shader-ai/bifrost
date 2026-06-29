package urai

import (
	"testing"
)

func TestConfidentialityEnabledByDefault(t *testing.T) {
	t.Setenv("URAI_GO_CONFIDENTIALITY", "")
	cfg := ConfigFromEnv()
	if !cfg.ConfidentialityEnabled {
		t.Fatal("expected confidentiality enabled by default")
	}
}

func TestConfidentialityKillSwitch(t *testing.T) {
	t.Setenv("URAI_GO_CONFIDENTIALITY", "false")
	cfg := ConfigFromEnv()
	if cfg.ConfidentialityEnabled {
		t.Fatal("expected confidentiality disabled when URAI_GO_CONFIDENTIALITY=false")
	}
}

func TestConfidentialityExplicitOn(t *testing.T) {
	t.Setenv("URAI_GO_CONFIDENTIALITY", "true")
	cfg := ConfigFromEnv()
	if !cfg.ConfidentialityEnabled {
		t.Fatal("expected confidentiality enabled when URAI_GO_CONFIDENTIALITY=true")
	}
}
