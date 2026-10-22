package fwmgr

import (
	"fmt"
	"os"
	"path/filepath"
)

// applyConfig validates content, atomically replaces the file at path, then
// runs reload. If reload fails it restores the previous file content (or
// removes the file if there was none) and re-runs reload, so a rejected
// configuration never stays active. It is OS-independent and unit-tested.
func applyConfig(path string, content []byte, validate func([]byte) error, reload func() error) error {
	if validate != nil {
		if err := validate(content); err != nil {
			return fmt.Errorf("reject configuration: %w", err)
		}
	}

	prev, had, err := readMaybe(path)
	if err != nil {
		return fmt.Errorf("read current configuration: %w", err)
	}

	if err := writeAtomic(path, content); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}

	if reload == nil {
		return nil
	}
	if err := reload(); err != nil {
		if rbErr := restore(path, prev, had); rbErr != nil {
			return fmt.Errorf("reload failed (%v); restoring previous configuration also failed: %w", err, rbErr)
		}
		if reload() != nil {
			return fmt.Errorf("reload failed and previous configuration could not be reactivated: %w", err)
		}
		return fmt.Errorf("reload rejected new configuration, rolled back: %w", err)
	}
	return nil
}

func readMaybe(path string) (content []byte, existed bool, err error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func restore(path string, prev []byte, had bool) error {
	if had {
		return writeAtomic(path, prev)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// writeAtomic writes content to a temp file in the same directory and renames
// it over path, so a concurrent reader never observes a partial file.
func writeAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fwcfg-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

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
	return os.Rename(name, path)
}
