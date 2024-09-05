//go:build windows
// +build windows

package installca

import (
	"os"
	"os/exec"
)

func InstallCA(x509Certificate []byte) error {
	f, err := os.CreateTemp(os.TempDir(), "tmp-*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = writeToCertificatePem(f, x509Certificate)
	f.Close()
	if err != nil {
		return err
	}

	cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", f.Name())
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
