package signer

import "testing"

func TestCoSignDataNonCadesFallsBackToSign(t *testing.T) {
	orig := signDataCompatFallbackFunc
	t.Cleanup(func() { signDataCompatFallbackFunc = orig })

	called := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		called = true
		if format != "xades" {
			t.Fatalf("formato inesperado en fallback cosign: %q", format)
		}
		if certificateID != "cert-1" {
			t.Fatalf("certificado inesperado en fallback cosign: %q", certificateID)
		}
		return "fallback-signature", nil
	}

	xmlDataB64 := "PHJvb3Q+ZGF0YTwvcm9vdD4="
	got, err := CoSignData(xmlDataB64, "cert-1", "", "xades", nil)
	if err != nil {
		t.Fatalf("error inesperado en fallback cosign: %v", err)
	}
	if !called {
		t.Fatalf("cosign no uso fallback a SignData para formato no CAdES")
	}
	if got != "fallback-signature" {
		t.Fatalf("firma inesperada en fallback cosign: %q", got)
	}
}

func TestCounterSignDataNonCadesFallsBackToSign(t *testing.T) {
	orig := signDataCompatFallbackFunc
	t.Cleanup(func() { signDataCompatFallbackFunc = orig })

	called := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		called = true
		if format != "pades" {
			t.Fatalf("formato inesperado en fallback countersign: %q", format)
		}
		if pin != "1234" {
			t.Fatalf("pin inesperado en fallback countersign: %q", pin)
		}
		return "fallback-signature", nil
	}

	pdfDataB64 := "JVBERi0xLjcK"
	got, err := CounterSignData(pdfDataB64, "cert-2", "1234", "pades", map[string]interface{}{
		"target": "tree",
	})
	if err != nil {
		t.Fatalf("error inesperado en fallback countersign: %v", err)
	}
	if !called {
		t.Fatalf("countersign no uso fallback a SignData para formato no CAdES")
	}
	if got != "fallback-signature" {
		t.Fatalf("firma inesperada en fallback countersign: %q", got)
	}
}

