// Copyright 2024 JC-Lab. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"github.com/youmark/pkcs8"
	"local-tls-proxy/ca"
	"local-tls-proxy/internal/streamcopy"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	patternSslIp = regexp.MustCompile("(\\d+)\\.([\\w\\d-]+)\\.(sslip\\.io)$")
)

func main() {
	var caKey string
	var caCert string
	var port int

	flag.StringVar(&caKey, "ca-key", "ca.key", "KeyPair key file path")
	flag.StringVar(&caCert, "ca-cert", "ca.pem", "KeyPair certificate file path")
	flag.IntVar(&port, "port", 5443, "server port")
	flag.Parse()

	caObj, err := initializeCa(caKey, caCert)
	if err != nil {
		log.Panicln(err)
	}
	_ = caObj

	certPool := x509.NewCertPool()
	certPool.AddCert(caObj.Cert)

	wildcardCert, err := caObj.GenerateLeafCert("*.127-0-0-1.sslip.io")
	if err != nil {
		log.Panicln(err)
	}

	_ = wildcardCert

	listener, err := tls.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port), &tls.Config{
		RootCAs: certPool,
		Certificates: []tls.Certificate{
			{
				PrivateKey:  wildcardCert.Key,
				Leaf:        wildcardCert.Cert,
				Certificate: [][]byte{wildcardCert.Cert.Raw, caObj.Cert.Raw},
			},
		},
		//GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		//	log.Println("GetCertificate : ", info)
		//	return nil, nil
		//},
	})
	if err != nil {
		log.Panicln(err)
	}

	log.Printf("Listening on %s", listener.Addr())

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Panicln(err)
		}

		go handleClient(client)
	}
}

func initializeCa(caKeyFile string, caCertFile string) (*ca.KeyPair, error) {
	var caObj *ca.KeyPair

	caKeyPem, err := readPemFile(caKeyFile)
	if err == nil {
		caCertPem, err := readPemFile(caCertFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read KeyPair certificate")
		}
		caObj = &ca.KeyPair{}
		caObj.Cert, err = x509.ParseCertificate(caCertPem.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse KeyPair certificate")
		}
		caObj.Key, err = pkcs8.ParsePKCS8PrivateKey(caKeyPem.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse KeyPair key")
		}
	} else if os.IsNotExist(err) {
		log.Println("Generate new caObj certificate...")

		caObj = &ca.KeyPair{}
		caObj.Key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate key")
		}
		caObj, err = ca.GenerateCA()
		if err != nil {
			return nil, err
		}

		caKeyRaw, err := pkcs8.MarshalPrivateKey(caObj.Key, nil, nil)
		if err != nil {
			return nil, err
		}
		err = writePemFile(caKeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyRaw})
		if err != nil {
			return nil, err
		}
		err = writePemFile(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caObj.Cert.Raw})
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Wrap(err, "failed to read KeyPair key")
	}

	return caObj, nil
}

func handleClient(client net.Conn) {
	defer client.Close()

	tlsConn := client.(*tls.Conn)
	err := tlsConn.Handshake()
	if err != nil {
		log.Println("handshake failed: ", err)
		return
	}

	serverName := tlsConn.ConnectionState().ServerName

	matches := patternSslIp.FindStringSubmatch(serverName)
	if len(matches) <= 0 {
		log.Println("unknown domain: %s", serverName)
		return
	}
	targetPort, err := strconv.ParseInt(matches[1], 10, 16)
	if err != nil {
		log.Printf("DOMAIN[%s] port parse failed: %v", serverName, err)
		return
	}
	targetAddr := strings.ReplaceAll(matches[2], "-", ".")

	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddr, targetPort))
	if err != nil {
		log.Printf("DOMAIN[%s] dial failed: %v", serverName, err)
		return
	}

	defer targetConn.Close()

	streamcopy.BiDirectionCopy(targetConn.(*net.TCPConn), tlsConn)
}

func readPemFile(name string) (*pem.Block, error) {
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return block, nil
}

func writePemFile(name string, block *pem.Block) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, block)
}
