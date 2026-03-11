package tests

import (
	"testing"

	"onprem-data-verifier/validator"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfiguration(t *testing.T) {
	// 1. Act: Get the internal config
	config := validator.GetDefaultConfig()

	// 2. Assert: Verify key policies are in place
	assert.Equal(t, 50, config.SizeThresholdGB)

	// Verify we have a good number of versions
	assert.Greater(t, len(config.SupportedVersions), 10)

	// Verify specific boundary versions exist
	assert.Contains(t, config.SupportedVersions, "25.20")
	assert.Contains(t, config.SupportedVersions, "22.18")

	// Verify we don't have duplicates (sanity check on the manual list)
	versionMap := make(map[string]bool)
	for _, v := range config.SupportedVersions {
		if versionMap[v] {
			t.Errorf("Duplicate version found in config: %s", v)
		}
		versionMap[v] = true
	}
}
