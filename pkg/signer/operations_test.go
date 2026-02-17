package signer

import "testing"

func TestCoSignDataNonCadesFallsBackToSign(t *testing.T) {
	origFallback := signDataCompatFallbackFunc
	origNative := signDataNativeMultiSignFunc
	t.Cleanup(func() {
		signDataCompatFallbackFunc = origFallback
		signDataNativeMultiSignFunc = origNative
	})

	calledFallback := false
	calledNative := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledFallback = true
		if format != "unknown" {
			t.Fatalf("formato inesperado en fallback cosign: %q", format)
		}
		if certificateID != "cert-1" {
			t.Fatalf("certificado inesperado en fallback cosign: %q", certificateID)
		}
		return "fallback-signature", nil
	}
	signDataNativeMultiSignFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledNative = true
		return "native-signature", nil
	}

	xmlDataB64 := "PHJvb3Q+ZGF0YTwvcm9vdD4="
	got, err := CoSignData(xmlDataB64, "cert-1", "", "unknown", nil)
	if err != nil {
		t.Fatalf("error inesperado en fallback cosign: %v", err)
	}
	if !calledFallback {
		t.Fatalf("cosign no uso fallback a SignData para formato no CAdES")
	}
	if calledNative {
		t.Fatalf("cosign no debe usar ruta nativa para formato desconocido")
	}
	if got != "fallback-signature" {
		t.Fatalf("firma inesperada en fallback cosign: %q", got)
	}
}

func TestCounterSignDataNonCadesFallsBackToSign(t *testing.T) {
	origFallback := signDataCompatFallbackFunc
	origNative := signDataNativeMultiSignFunc
	t.Cleanup(func() {
		signDataCompatFallbackFunc = origFallback
		signDataNativeMultiSignFunc = origNative
	})

	calledFallback := false
	calledNative := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledFallback = true
		if format != "unknown" {
			t.Fatalf("formato inesperado en fallback countersign: %q", format)
		}
		if pin != "1234" {
			t.Fatalf("pin inesperado en fallback countersign: %q", pin)
		}
		return "fallback-signature", nil
	}
	signDataNativeMultiSignFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledNative = true
		return "native-signature", nil
	}

	xmlDataB64 := "PHJvb3Q+ZGF0YTwvcm9vdD4="
	got, err := CounterSignData(xmlDataB64, "cert-2", "1234", "unknown", map[string]interface{}{
		"target": "tree",
	})
	if err != nil {
		t.Fatalf("error inesperado en fallback countersign: %v", err)
	}
	if !calledFallback {
		t.Fatalf("countersign no uso fallback a SignData para formato no CAdES")
	}
	if calledNative {
		t.Fatalf("countersign no debe usar ruta nativa para formato desconocido")
	}
	if got != "fallback-signature" {
		t.Fatalf("firma inesperada en fallback countersign: %q", got)
	}
}

func TestCoSignDataXadesUsesNativeMultiSignRoute(t *testing.T) {
	origFallback := signDataCompatFallbackFunc
	origNative := signDataNativeMultiSignFunc
	t.Cleanup(func() {
		signDataCompatFallbackFunc = origFallback
		signDataNativeMultiSignFunc = origNative
	})

	calledFallback := false
	calledNative := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledFallback = true
		return "fallback-signature", nil
	}
	signDataNativeMultiSignFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledNative = true
		if format != "xades" {
			t.Fatalf("formato inesperado en ruta nativa cosign: %q", format)
		}
		return "native-signature", nil
	}

	xmlDataB64 := "PHJvb3Q+ZGF0YTwvcm9vdD4="
	got, err := CoSignData(xmlDataB64, "cert-1", "", "xades", nil)
	if err != nil {
		t.Fatalf("error inesperado en ruta nativa cosign xades: %v", err)
	}
	if !calledNative {
		t.Fatalf("cosign xades debe usar ruta nativa")
	}
	if calledFallback {
		t.Fatalf("cosign xades no debe usar fallback generico")
	}
	if got != "native-signature" {
		t.Fatalf("firma inesperada en ruta nativa cosign xades: %q", got)
	}
}

func TestCounterSignDataPadesUsesNativeMultiSignRoute(t *testing.T) {
	origFallback := signDataCompatFallbackFunc
	origNative := signDataNativeMultiSignFunc
	t.Cleanup(func() {
		signDataCompatFallbackFunc = origFallback
		signDataNativeMultiSignFunc = origNative
	})

	calledFallback := false
	calledNative := false
	signDataCompatFallbackFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledFallback = true
		return "fallback-signature", nil
	}
	signDataNativeMultiSignFunc = func(dataB64 string, certificateID string, pin string, format string, options map[string]interface{}) (string, error) {
		calledNative = true
		if format != "pades" {
			t.Fatalf("formato inesperado en ruta nativa countersign: %q", format)
		}
		if pin != "1234" {
			t.Fatalf("pin inesperado en ruta nativa countersign: %q", pin)
		}
		return "native-signature", nil
	}

	pdfDataB64 := "JVBERi0xLjcK"
	got, err := CounterSignData(pdfDataB64, "cert-2", "1234", "pades", map[string]interface{}{
		"target": "tree",
	})
	if err != nil {
		t.Fatalf("error inesperado en ruta nativa countersign pades: %v", err)
	}
	if !calledNative {
		t.Fatalf("countersign pades debe usar ruta nativa")
	}
	if calledFallback {
		t.Fatalf("countersign pades no debe usar fallback generico")
	}
	if got != "native-signature" {
		t.Fatalf("firma inesperada en ruta nativa countersign pades: %q", got)
	}
}
