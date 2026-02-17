package signer

import (
	"testing"

	"github.com/beevik/etree"
)

func TestCollectXadesSignatureElements(t *testing.T) {
	root := etree.NewElement("root")
	sig1 := root.CreateElement("ds:Signature")
	_ = sig1.CreateElement("ds:SignedInfo")
	container := root.CreateElement("child")
	_ = container.CreateElement("xades:Signature")

	sigs := collectXadesSignatureElements(root)
	if len(sigs) != 2 {
		t.Fatalf("numero inesperado de Signature en XML: %d", len(sigs))
	}
}

func TestFilterLeafSignatureElements(t *testing.T) {
	root := etree.NewElement("root")
	parent := root.CreateElement("ds:Signature")
	_ = parent.CreateElement("ds:Signature")
	leaf := root.CreateElement("xades:Signature")

	sigs := collectXadesSignatureElements(root)
	leafs := filterLeafSignatureElements(sigs)
	if len(leafs) != 2 {
		t.Fatalf("se esperaban 2 firmas hoja, obtenido: %d", len(leafs))
	}

	foundParent := false
	foundNested := false
	foundLeaf := false
	for _, s := range leafs {
		if s == parent {
			foundParent = true
		}
		if s != nil && s.Parent() == parent {
			foundNested = true
		}
		if s == leaf {
			foundLeaf = true
		}
	}
	if foundParent {
		t.Fatalf("la firma padre no debe considerarse hoja")
	}
	if !foundNested || !foundLeaf {
		t.Fatalf("firmas hoja no detectadas correctamente")
	}
}

func TestXMLLocalName(t *testing.T) {
	if got := xmlLocalName("ds:Signature"); got != "Signature" {
		t.Fatalf("local name inesperado: %q", got)
	}
	if got := xmlLocalName("Signature"); got != "Signature" {
		t.Fatalf("local name inesperado sin prefijo: %q", got)
	}
}
