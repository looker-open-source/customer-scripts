package tests

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"onprem-data-verifier/validator"

	"github.com/stretchr/testify/assert"
)

// Helper to create a dummy file with specific content
func createTempFile(t *testing.T, content string) (string, string) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test_data.txt")
	err := os.WriteFile(filePath, []byte(content), 0644)
	assert.NoError(t, err)
	return tmpDir, filePath
}

func TestVerifyChecksumMap_WithAbsolutePaths(t *testing.T) {
	// 1. Arrange: Create a manifest with customer-side absolute paths
	manifestContent := `
7be77e6bd5780b224d933d0b7e2e1c5f  /customerName_looker_fs_backup.tar.gz.enc
8d8e91a5d73aa26aa34a517cbf51530a  /tmp/backups/customerName_looker_db_backup.sql.gz.enc
e11cc646fce9be85cca717d85e64d4c6  /home/looker/backup/customerName_looker_cmk_key
`
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "_backup.md5")
	err := os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	assert.NoError(t, err)

	// 2. Act: Parse the manifest
	checksums, err := validator.ParseMD5Manifest(manifestPath)

	// 3. Assert: Verify we extracted only the filenames, not the full paths
	assert.NoError(t, err)
	assert.Len(t, checksums, 3)

	// We expect the key to be JUST the filename
	assert.Equal(t, "7be77e6bd5780b224d933d0b7e2e1c5f", checksums["customerName_looker_fs_backup.tar.gz.enc"])
	assert.Equal(t, "e11cc646fce9be85cca717d85e64d4c6", checksums["customerName_looker_cmk_key"])
}

func TestCalculateChecksum(t *testing.T) {
	// 1. Arrange: Create a file with known content
	content := "LookerOnPremBackup2024"
	_, filePath := createTempFile(t, content)

	// Calculate expected MD5 using Go's standard library
	hasher := md5.New()
	hasher.Write([]byte(content))
	expectedHash := fmt.Sprintf("%x", hasher.Sum(nil))

	// 2. Act: Use our validator function
	actualHash, err := validator.CalculateMD5(filePath)

	// 3. Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, actualHash, "Checksums should match")
}

func TestVerifyChecksumMap(t *testing.T) {
	// 1. Arrange: Create a mock MD5 manifest file
	// The format from the bash script is: "hash  filename" (note two spaces)
	manifestContent := `
d41d8cd98f00b204e9800998ecf8427e  empty.txt
5a105e8b9d40e1329780d62ea2265d8a  data.sql.gz
invalid_line_garbage
`
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "_backup.md5")
	err := os.WriteFile(manifestPath, []byte(manifestContent), 0644)
	assert.NoError(t, err)

	// 2. Act: Parse the manifest
	checksums, err := validator.ParseMD5Manifest(manifestPath)

	// 3. Assert
	assert.NoError(t, err)
	assert.Len(t, checksums, 2)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", checksums["empty.txt"])
	assert.Equal(t, "5a105e8b9d40e1329780d62ea2265d8a", checksums["data.sql.gz"])
}

func TestVerifyFileIntegrity(t *testing.T) {
	// 1. Arrange: Create a real file and a matching entry in a map
	content := "IntegrityCheck"
	dir, filePath := createTempFile(t, content)
	filename := filepath.Base(filePath)

	// Calculate hash
	hasher := md5.New()
	hasher.Write([]byte(content))
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	expectedChecksums := map[string]string{
		filename: hash,
	}

	// 2. Act
	valid, err := validator.VerifyFile(dir, filename, expectedChecksums[filename])

	// 3. Assert
	assert.NoError(t, err)
	assert.True(t, valid, "File should verify successfully against the hash")
}
