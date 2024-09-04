// Copyright 2024 JC-Lab. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"net"
	"time"
)

type KeyPair struct {
	Key  crypto.PrivateKey
	Cert *x509.Certificate
}

func GenerateCA() (*KeyPair, error) {
	// CA의 Private Key 생성
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}

	// KeyPair 인증서 템플릿 생성
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"local-tls-proxy"},
			CommonName:   "local-tls-proxy KeyPair",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10년 유효
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// KeyPair 인증서 자체 서명
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return &KeyPair{
		Key:  caKey,
		Cert: caCert,
	}, nil
}

func (ca *KeyPair) GenerateLeafCert(domain string) (*KeyPair, error) {
	var isDomain bool = false
	ip := net.ParseIP(domain)
	if ip == nil {
		isDomain = true
		ip = net.ParseIP("127.0.0.1")
	}

	// Leaf 인증서의 Private Key 생성
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf private key: %v", err)
	}

	// Leaf 인증서 템플릿 생성
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1년 유효
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{ip},
	}
	if isDomain {
		leafTemplate.DNSNames = []string{domain}
	}

	// Leaf 인증서 서명
	certBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return &KeyPair{
		Key:  leafKey,
		Cert: cert,
	}, nil
}
