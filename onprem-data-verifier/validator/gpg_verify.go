package validator

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ParseGPGColons extracts ALL Key IDs (Primary + Subkeys) from the raw output.
func ParseGPGColons(output string) ([]string, error) {
	var keyIDs []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// We want both Primary keys (pub) and Subkeys (sub)
		if strings.HasPrefix(line, "pub:") || strings.HasPrefix(line, "sub:") {
			parts := strings.Split(line, ":")
			// Field 5 (index 4) is the Long Key ID
			if len(parts) >= 5 {
				keyIDs = append(keyIDs, parts[4])
			}
		}
	}

	if len(keyIDs) == 0 {
		return nil, fmt.Errorf("no keys found in GPG output")
	}
	return keyIDs, nil
}

// GetKeyIDsFromEmail asks the local GPG keyring for ALL Key IDs associated with an email
func GetKeyIDsFromEmail(email string) ([]string, error) {
	cmd := exec.Command("gpg", "--list-keys", "--with-colons", email)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("public key not found for '%s'. Error: %s", email, stderr.String())
	}

	return ParseGPGColons(stdout.String())
}

// VerifyRecipient checks if the file is encrypted for ANY of the valid Key IDs
func VerifyRecipient(filePath string, validKeyIDs []string) (bool, error) {
	cmd := exec.Command("gpg", "--list-packets", filePath)
	var stdout, stderr bytes.Buffer // <--- IMPROVEMENT: Capture stderr
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Include stderr in the error message so we know WHY it failed
		return false, fmt.Errorf("failed to read GPG packets: %v | %s", err, stderr.String())
	}

	output := stdout.String()

	// Check if the file is encrypted for ANY of the valid IDs
	for _, id := range validKeyIDs {
		if strings.Contains(output, id) {
			return true, nil
		}
	}

	return false, nil // None of the keys matched
}
