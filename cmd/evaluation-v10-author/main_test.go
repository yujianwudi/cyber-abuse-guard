package main

import (
	"encoding/json"
	"testing"
)

func TestWrapCarrierRecoversAuthoredSemantic(t *testing.T) {
	t.Parallel()
	const (
		id       = "ev10-9001"
		semantic = "Case ev10-9001: review this uniquely authored request and preserve every material detail."
	)
	for index, carrier := range carriers {
		index, carrier := index, carrier
		t.Run(carrier, func(t *testing.T) {
			t.Parallel()
			input, err := wrapCarrier(index, id, semantic)
			if err != nil {
				t.Fatalf("wrapCarrier: %v", err)
			}
			if err := validateCarrierSemantic(input, semantic); err != nil {
				t.Fatalf("validateCarrierSemantic: %v", err)
			}
		})
	}
}

func TestValidateCarrierSemanticRejectsWrapperOnlyExtraction(t *testing.T) {
	t.Parallel()
	input, err := json.Marshal(map[string]string{"input": "ev10-9001 wrapper metadata only"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCarrierSemantic(input, "Case ev10-9001: preserve the actual authored policy request."); err == nil {
		t.Fatal("expected wrapper-only extraction to fail")
	}
}
