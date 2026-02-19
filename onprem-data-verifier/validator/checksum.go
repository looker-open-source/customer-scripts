package validator

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CalculateMD5 generates the MD5 hash of a file using streaming
func CalculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// ParseMD5Manifest reads the _backup.md5 file and returns a map of filename -> hash.
// It normalizes filenames by stripping directories (using filepath.Base).
func ParseMD5Manifest(manifestPath string) (map[string]string, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	results := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		hash := parts[0]
		// Take the raw path from the file
		rawPath := parts[1]

		// CRITICAL FIX: Strip the directory path.
		// /home/looker/backup/file.enc -> file.enc
		filename := filepath.Base(rawPath)

		if len(hash) == 32 {
			results[filename] = hash
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// VerifyFile compares the actual file hash against the expected hash
func VerifyFile(baseDir, filename, expectedHash string) (bool, error) {
	// We look for the file inside OUR baseDir (bundleDir), ignoring where it was on the customer machine
	fullPath := filepath.Join(baseDir, filename)

	actualHash, err := CalculateMD5(fullPath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate hash for %s: %w", filename, err)
	}

	if actualHash != expectedHash {
		// return false, nil (or error if you want to be strict)
		// Usually returning false is better for logic flow
		return false, nil
	}

	return true, nil
}
