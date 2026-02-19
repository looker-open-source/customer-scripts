package tests

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"onprem-data-verifier/metadata"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataGeneration(t *testing.T) {
	// 1. Arrange: Initialize the struct directly
	report := metadata.Report{
		CustomerName:      "lookersre-instance-1",
		InstanceID:        "7b973058-f7e0-49f7-9262-54e1987659bc",
		GeneratedAt:       "01-06=2026",
		FSTotalSizeBytes:  524288000, // 500MB
		DBTotalSizeBytes:  104857600, // 100MB
		TableCount:        75,
		LookerVer:         "23.18.0",
		CmkStatus:         "Valid",
		DurationInSeconds: 2.43,
	}

	// 2. Assert: Verify memory values (Go struct fields)
	assert.Equal(t, "lookersre-instance-1", report.CustomerName)
	assert.Equal(t, int64(524288000), report.FSTotalSizeBytes)

	// 3. Act: Serialize to JSON
	jsonData, err := report.ToJSON()
	assert.NoError(t, err)

	// 4. Assert: Verify JSON tags
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	assert.NoError(t, err)

	// Verify keys match your NEW json struct tags
	assert.Equal(t, "lookersre-instance-1", result["customer_name"])

	// UPDATED: Checking for "fs_total_size_bytes" instead of "total_size_bytes"
	assert.Equal(t, float64(524288000), result["fs_total_size_bytes"])

	// UPDATED: Checking for "db_total_size_bytes" instead of "size_bytes"
	assert.Equal(t, float64(104857600), result["db_total_size_bytes"])

	assert.Equal(t, "Valid", result["cmk_status"])
}

func TestReport_Save(t *testing.T) {
	// Setup a sample report
	report := &metadata.Report{
		CustomerName:      "Test Customer",
		InstanceID:        "inst-999",
		DurationInSeconds: 1.5,
	}

	t.Run("Scenario 1: Default Behavior (metadata.json)", func(t *testing.T) {
		// When we pass "metadata.json", it should save in the current directory
		filename := "metadata.json"

		// Cleanup: delete the file after test
		defer os.Remove(filename)

		err := report.Save(filename)
		require.NoError(t, err)

		// Check if file exists in current directory
		assert.FileExists(t, filename)
	})

	t.Run("Scenario 2: Valid Custom Path", func(t *testing.T) {
		// Use a temp dir to simulate a valid custom location
		tmpDir := t.TempDir()
		customPath := filepath.Join(tmpDir, "custom_report.json")

		err := report.Save(customPath)
		require.NoError(t, err)

		// Verify it went to the temp dir
		assert.FileExists(t, customPath)
	})

	t.Run("Scenario 3: Invalid Directory (Fallback)", func(t *testing.T) {
		// Define a path in a directory that definitely does not exist
		// e.g. "./this/folder/does/not/exist/fallback.json"
		badDir := filepath.Join("this", "folder", "does", "not", "exist")
		filename := "fallback.json"
		badPath := filepath.Join(badDir, filename)

		// Cleanup: The fallback will save to current dir, so we must delete it there
		defer os.Remove(filename)

		err := report.Save(badPath)
		require.NoError(t, err)

		// 1. It should exist in the CURRENT directory (fallback)
		assert.FileExists(t, filename, "Should have fallen back to current directory")

		// 2. It should NOT exist in the bad directory
		assert.NoDirExists(t, badDir)
	})

	t.Run("Scenario 4: Verify JSON Content", func(t *testing.T) {
		// Save to a temp file
		tmpPath := filepath.Join(t.TempDir(), "content_test.json")
		err := report.Save(tmpPath)
		require.NoError(t, err)

		// Read it back
		data, err := os.ReadFile(tmpPath)
		require.NoError(t, err)

		// Parse it to verify structure
		var savedReport metadata.Report
		err = json.Unmarshal(data, &savedReport)
		require.NoError(t, err)

		// Assert values match
		assert.Equal(t, "Test Customer", savedReport.CustomerName)
		assert.Equal(t, 1.5, savedReport.DurationInSeconds)
	})
}
