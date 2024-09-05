//go:build linux
// +build linux

package installca

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
)

func InstallCA(x509Certificate []byte) error {
	hash := sha256.New()
	hash.Write(x509Certificate)
	fingerprint := hash.Sum(nil)
	if err := writeToCertificatePemFile(filepath.Join("/usr/local/share/ca-certificates", "local-tls-proxy-"+hex.EncodeToString(fingerprint)+".crt"), x509Certificate); err != nil {
		return err
	}

	cmd := exec.Command("update-ca-certificates")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
