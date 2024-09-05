package installca

import (
	"encoding/pem"
	"io"
	"os"
)

func writeToCertificatePem(out io.Writer, raw []byte) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	}
	return pem.Encode(out, block)
}

func writeToCertificatePemFile(name string, raw []byte) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeToCertificatePem(f, raw)
}
