//go:build cgo
// +build cgo

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/miekg/pkcs11"
)

type cryptoSignerPKCS11 struct {
	p        *pkcs11.Ctx
	session  pkcs11.SessionHandle
	keyObj   pkcs11.ObjectHandle
	pubKey   crypto.PublicKey
	cert     *x509.Certificate
	pin      string
	loggedIn bool
}

func (s *cryptoSignerPKCS11) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *cryptoSignerPKCS11) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.pin != "" && !s.loggedIn {
		if err := s.p.Login(s.session, pkcs11.CKU_USER, s.pin); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			log.Printf("[PKCS11] Error en Login previo a firma: %v", err)
		} else {
			s.loggedIn = true
		}
	}

	var dataToSign []byte
	switch s.pubKey.(type) {
	case *rsa.PublicKey:
		// For RSA, CKM_RSA_PKCS only does PKCS#1 v1.5 padding (00 01 FF...FF 00).
		// We must prepend the ASN.1 DigestInfo.
		hashAlg := opts.HashFunc()
		prefix, ok := pkcs1Prefix[hashAlg]
		if !ok {
			return nil, fmt.Errorf("PKCS11: hash function %v no soportada para RSA", hashAlg)
		}
		dataToSign = append(prefix, digest...)
		if err := s.p.SignInit(s.session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
		}, s.keyObj); err != nil {
			return nil, fmt.Errorf("SignInit CKM_RSA_PKCS fallido: %v", err)
		}
	case *ecdsa.PublicKey:
		dataToSign = digest
		if err := s.p.SignInit(s.session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
		}, s.keyObj); err != nil {
			return nil, fmt.Errorf("SignInit CKM_ECDSA fallido: %v", err)
		}
	default:
		return nil, fmt.Errorf("PKCS11: Tipo de clave pública no soportado")
	}

	sig, err := s.p.Sign(s.session, dataToSign)
	if err != nil {
		return nil, fmt.Errorf("PKCS11 Sign fallido: %v", err)
	}

	return sig, nil
}

func (s *cryptoSignerPKCS11) Close() {
	if s.loggedIn {
		_ = s.p.Logout(s.session)
	}
	_ = s.p.CloseSession(s.session)
	s.p.Finalize()
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func GetPKCS11SignerAndCert(certDER []byte, pin string, options map[string]interface{}) (*cryptoSignerPKCS11, error) {
	_, hints, includePKCS11, _ := resolveCertstoreOptions(options)
	if !includePKCS11 {
		return nil, fmt.Errorf("pkcs11 deshabilitado por opciones")
	}

	modules := signerPKCS11ModuleCandidates(hints)
	for _, modulePath := range modules {
		if _, err := os.Stat(modulePath); err != nil {
			continue
		}
		p := pkcs11.New(modulePath)
		if p == nil {
			continue
		}
		if err := p.Initialize(); err != nil {
			continue
		}
		slots, err := p.GetSlotList(true)
		if err != nil {
			p.Finalize()
			continue
		}
		for _, slot := range slots {
			session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
			if err != nil {
				continue
			}

			loggedIn := false
			if pin != "" {
				if err := p.Login(session, pkcs11.CKU_USER, pin); err == nil || err == pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
					loggedIn = true
				}
			}

			certObj, keyID, err := findPKCS11CertObjectAndID(p, session, certDER)
			if err == nil && certObj != 0 && len(keyID) > 0 {
				keyObj, errKey := findPKCS11PrivateKeyByID(p, session, keyID)
				if errKey == nil && keyObj != 0 {
					cert, errParse := x509.ParseCertificate(certDER)
					if errParse == nil {
						log.Printf("[PKCS11] Clave privada encontrada. Modulo=%s Slot=%d", modulePath, slot)
						return &cryptoSignerPKCS11{
							p:        p,
							session:  session,
							keyObj:   keyObj,
							pubKey:   cert.PublicKey,
							cert:     cert,
							pin:      pin,
							loggedIn: loggedIn,
						}, nil
					}
				}
			}

			if loggedIn {
				_ = p.Logout(session)
			}
			_ = p.CloseSession(session)
		}
		p.Finalize()
	}

	return nil, fmt.Errorf("no se encontro la clave en ningún modulo PKCS11")
}
