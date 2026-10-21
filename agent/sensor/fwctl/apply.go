package fwctl

import (
	"fmt"
	"os"
	"path/filepath"
)

// Validator checks a candidate configuration before it is written.
type Validator func(content []byte) error

// Reloader notifies the firewall that its on-disk configuration changed.
type Reloader func() error

// atomicApply validates content, replaces the file at path atomically, then
// calls reload. If reload fails, the previous file content is restored and the
// reload error is returned, so a bad configuration never stays active.
//
// It is the shared core of the per-firewall ApplyConfig methods and is kept
// free of any Windows dependency so it can be exercised on any platform.
func atomicApply(path string, content []byte, validate Validator, reload Reloader) error {
	if validate != nil {
		if err := validate(content); err != nil {
			return fmt.Errorf("reject configuration: %w", err)
		}
	}

	backup, hadBackup, err := readIfExists(path)
	if err != nil {
		return fmt.Errorf("read current configuration: %w", err)
	}

	if err := writeFileAtomic(path, content); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}

	if reload == nil {
		return nil
	}
	if err := reload(); err != nil {
		// roll back to the previous configuration (or remove the file if there
		// was none) and try to reload it so the firewall is left consistent.
		if hadBackup {
			if rbErr := writeFileAtomic(path, backup); rbErr != nil {
				return fmt.Errorf("reload failed (%v) and rollback failed (%v)", err, rbErr)
			}
		} else {
			_ = os.Remove(path)
		}
		if reload() != nil {
			return fmt.Errorf("reload failed and could not restore previous configuration: %w", err)
		}
		return fmt.Errorf("reload rejected new configuration, rolled back: %w", err)
	}
	return nil
}

func readIfExists(path string) (content []byte, existed bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

// writeFileAtomic writes content to a temp file in the same directory and
// renames it over path, so a reader never sees a half-written file.
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".fwcfg-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
