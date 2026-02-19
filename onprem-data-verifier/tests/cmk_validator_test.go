package tests

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"onprem-data-verifier/validator"

	"github.com/stretchr/testify/assert"
)

func createTempCMK(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "cmk_key")
	// write without newline to simulate exact key content
	err := os.WriteFile(filePath, []byte(content), 0600)
	assert.NoError(t, err)
	return filePath
}

func TestCMKValidation_Base64(t *testing.T) {
	// 1. Arrange: A valid 32-byte key encoded in Base64 (44 chars)
	// 32 bytes of 'a'
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 'a'
	}
	base64Key := base64.StdEncoding.EncodeToString(raw) // Length should be 44

	path := createTempCMK(t, base64Key)

	// 2. Act
	valid, format, err := validator.ValidateCMK(path)

	// 3. Assert
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, "Base64", format)
}

func TestCMKValidation_Raw32(t *testing.T) {
	// 1. Arrange: A valid 32-byte raw key (not base64 encoded)
	rawKey := "12345678901234567890123456789012" // Exactly 32 chars
	path := createTempCMK(t, rawKey)

	// 2. Act
	valid, format, err := validator.ValidateCMK(path)

	// 3. Assert
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, "Raw", format)
}

func TestCMKValidation_InvalidLength(t *testing.T) {
	// 1. Arrange: Invalid length (e.g., 33 chars)
	badKey := "123456789012345678901234567890123"
	path := createTempCMK(t, badKey)

	// 2. Act
	valid, _, err := validator.ValidateCMK(path)

	// 3. Assert
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "invalid CMK length")
}

func TestCMKValidation_CorruptBase64(t *testing.T) {
	// 1. Arrange: 44 chars but invalid base64 content
	// '!' is not a valid base64 character
	badKey := "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	path := createTempCMK(t, badKey)

	// 2. Act
	valid, _, err := validator.ValidateCMK(path)

	// 3. Assert
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "illegal base64 data")
}
