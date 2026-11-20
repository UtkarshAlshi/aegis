package pki

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const maxRevocations = 1 << 20

var serialHex = regexp.MustCompile(`^[1-9a-f][0-9a-f]{0,39}$`)

func readRevocations(path string) (map[string]bool, error) {
	raw, err := ReadFile(path, maxRevocations)
	if err != nil {
		return nil, errors.New("revocation list unavailable")
	}
	result := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		if !serialHex.MatchString(value) {
			return nil, errors.New("malformed revocation list")
		}
		result[value] = true
	}
	return result, nil
}

func Revoke(path, serial string) error {
	if !serialHex.MatchString(serial) {
		return errors.New("invalid certificate serial")
	}
	lock := path + ".lock"
	if err := os.Mkdir(lock, 0700); err != nil {
		return errors.New("revocation list is locked or inaccessible")
	}
	defer os.Remove(lock)
	entries, err := readRevocations(path)
	if err != nil {
		return err
	}
	if entries[serial] {
		return nil
	}
	entries[serial] = true
	list := make([]string, 0, len(entries))
	for value := range entries {
		list = append(list, value)
	}
	slices.Sort(list)
	raw := strings.Join(list, "\n") + "\n"
	if len(raw) > maxRevocations {
		return errors.New("revocation list exceeds size limit")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".aegis-revocations-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.WriteString(raw)
	syncErr := f.Sync()
	if err := errors.Join(writeErr, syncErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
