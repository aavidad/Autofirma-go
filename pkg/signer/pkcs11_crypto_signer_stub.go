//go:build !cgo
// +build !cgo

package signer

import (
	"crypto"
	"fmt"
	"io"
)

type cryptoSignerPKCS11 struct{}

func (s *cryptoSignerPKCS11) Public() crypto.PublicKey {
	return nil
}

func (s *cryptoSignerPKCS11) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("PKCS11 no est\u00e1 soportado sin CGO")
}

func (s *cryptoSignerPKCS11) Close() {}

func GetPKCS11SignerAndCert(certDER []byte, pin string, options map[string]interface{}) (*cryptoSignerPKCS11, error) {
	return nil, fmt.Errorf("CGO deshabilitado, PKCS11 no soportado")
}
