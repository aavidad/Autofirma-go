// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Diputacion de Granada
// Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

//go:build linux && cgo
// +build linux,cgo

package signer

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"autofirma-host/pkg/protocol"

	"github.com/miekg/pkcs11"
)

func signPKCS1WithPKCS11(preSignData []byte, cert *protocol.Certificate, _ string, options map[string]interface{}) ([]byte, error) {
	if cert == nil || len(cert.Content) == 0 {
		return nil, fmt.Errorf("certificado invalido para firma PKCS11")
	}
	if len(preSignData) == 0 {
		return nil, fmt.Errorf("datos de prefirma vacios")
	}

	_, hints, includePKCS11, _ := resolveCertstoreOptions(options)
	if !includePKCS11 {
		return nil, fmt.Errorf("pkcs11 deshabilitado por opciones")
	}
	modules := signerPKCS11ModuleCandidates(hints)
	if len(modules) == 0 {
		return nil, fmt.Errorf("sin modulos PKCS11 disponibles")
	}
	pin := strings.TrimSpace(optionString(options, "pin", ""))
	if pin == "" {
		pin = strings.TrimSpace(optionString(options, "_pin", ""))
	}

	var lastErr error
	for _, modulePath := range modules {
		if _, err := os.Stat(modulePath); err != nil {
			continue
		}
		p := pkcs11.New(modulePath)
		if p == nil {
			continue
		}
		if err := p.Initialize(); err != nil {
			lastErr = err
			continue
		}
		slots, err := p.GetSlotList(true)
		if err != nil {
			p.Finalize()
			lastErr = err
			continue
		}
		for _, slot := range slots {
			session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
			if err != nil {
				lastErr = err
				continue
			}

			// First try without login; many environments keep authenticated session context.
			if sig, err := signPKCS1InSessionByCert(p, session, cert.Content, preSignData); err == nil && len(sig) > 0 {
				_ = p.CloseSession(session)
				p.Finalize()
				return sig, nil
			} else if err != nil {
				lastErr = err
			}

			if pin != "" {
				if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
					lastErr = err
				}
				if sig, err := signPKCS1InSessionByCert(p, session, cert.Content, preSignData); err == nil && len(sig) > 0 {
					_ = p.Logout(session)
					_ = p.CloseSession(session)
					p.Finalize()
					return sig, nil
				} else if err != nil {
					lastErr = err
				}
				_ = p.Logout(session)
			}
			_ = p.CloseSession(session)
		}
		p.Finalize()
	}
	if lastErr != nil {
		return nil, fmt.Errorf("firma PKCS11 directa fallida: %w", lastErr)
	}
	return nil, fmt.Errorf("no se encontro clave PKCS11 asociada al certificado")
}

func signPKCS1InSessionByCert(p *pkcs11.Ctx, session pkcs11.SessionHandle, certDER []byte, preSignData []byte) ([]byte, error) {
	certObj, keyID, err := findPKCS11CertObjectAndID(p, session, certDER)
	if err != nil {
		return nil, err
	}
	if certObj == 0 {
		return nil, fmt.Errorf("certificado no encontrado en token")
	}
	if len(keyID) == 0 {
		return nil, fmt.Errorf("certificado PKCS11 sin CKA_ID")
	}
	keyObj, err := findPKCS11PrivateKeyByID(p, session, keyID)
	if err != nil {
		return nil, err
	}
	if keyObj == 0 {
		return nil, fmt.Errorf("clave privada no encontrada para CKA_ID")
	}
	if err := p.SignInit(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
	}, keyObj); err != nil {
		return nil, err
	}
	return p.Sign(session, preSignData)
}

func findPKCS11CertObjectAndID(p *pkcs11.Ctx, session pkcs11.SessionHandle, certDER []byte) (pkcs11.ObjectHandle, []byte, error) {
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}); err != nil {
		return 0, nil, err
	}
	objects, _, err := p.FindObjects(session, 256)
	_ = p.FindObjectsFinal(session)
	if err != nil {
		return 0, nil, err
	}
	for _, obj := range objects {
		attrs, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attrs) < 2 {
			continue
		}
		if bytes.Equal(attrs[0].Value, certDER) {
			return obj, attrs[1].Value, nil
		}
	}
	return 0, nil, nil
}

func findPKCS11PrivateKeyByID(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyID []byte) (pkcs11.ObjectHandle, error) {
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}); err != nil {
		return 0, err
	}
	objects, _, err := p.FindObjects(session, 16)
	_ = p.FindObjectsFinal(session)
	if err != nil {
		return 0, err
	}
	if len(objects) == 0 {
		return 0, nil
	}
	return objects[0], nil
}

func signerPKCS11ModuleCandidates(hints []string) []string {
	if len(hints) > 0 {
		return hints
	}
	return []string{
		"/usr/lib/opensc-pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
		"/usr/lib64/opensc-pkcs11.so",
		"/usr/lib/pkcs11/opensc-pkcs11.so",
		"/usr/local/lib/opensc-pkcs11.so",
	}
}
