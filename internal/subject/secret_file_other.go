//go:build !linux

package subject

import (
	"errors"
	"fmt"
	"os"
)

func openSecretFile(path string) (*os.File, error) {
	// The hardened deployment target is Linux, where openSecretFile uses
	// O_NOFOLLOW. Preserve the prior explicit symlink rejection elsewhere.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("subject: inspect HMAC secret file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("subject: HMAC secret file must not be a symbolic link")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("subject: open HMAC secret file: %w", err)
	}
	return file, nil
}
