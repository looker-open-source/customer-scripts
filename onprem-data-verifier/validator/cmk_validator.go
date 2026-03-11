package validator

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// ValidateCMK checks if the provided key file contains a valid Looker CMK.
// Returns: isValid, format ("Raw" or "Base64"), error
func ValidateCMK(filePath string) (bool, string, error) {
	// 1. Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to read CMK file: %w", err)
	}

	// 2. CHECK RAW BINARY FIRST (Safety Check)
	// If the file is exactly 32 bytes, it is likely a Raw Binary Key.
	// We do this BEFORE trimming to avoid stripping valid key bytes that look like whitespace (e.g., 0x0A).
	if len(data) == 32 {
		return true, "Raw", nil
	}

	// 3. Clean input for Text/Base64 checks
	// It's safe to trim now because we know it wasn't a perfect 32-byte binary file.
	content := strings.TrimSpace(string(data))
	length := len(content)

	switch length {
	case 32:
		// It was likely 33+ bytes (Key + Newline) and trimming revealed it's 32 bytes.
		// This implies it was treated as a text string.
		return true, "Raw", nil

	case 44:
		// Potential Base64 Encoded Key.
		// We must verify it actually decodes to valid bytes.
		_, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return false, "", fmt.Errorf("CMK has length 44 but contains illegal base64 data: %w", err)
		}
		return true, "Base64", nil

	default:
		return false, "", fmt.Errorf("invalid CMK length: got %d bytes (after trimming). Expected 32 (Raw) or 44 (Base64)", length)
	}
}
