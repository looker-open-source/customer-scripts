package tests

import (
	"compress/gzip"
	"onprem-data-verifier/validator"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test for the helper function
func TestIsLookerVersionSupported(t *testing.T) {
	supported := []string{"23.18", "24.0"}

	tests := []struct {
		input    string
		expected bool
	}{
		{"23.18.0", true},  // Prefix match
		{"23.18", true},    // Exact match
		{"24.0.5", true},   // Prefix match
		{"22.0.0", false},  // Too old
		{"23.19.0", false}, // Not in list
		{"invalid", false}, // Garbage input
	}

	for _, tc := range tests {
		got := validator.IsLookerVersionSupported(tc.input, supported)
		assert.Equal(t, tc.expected, got, "Failed check for version: %s", tc.input)
	}
}

// Main test for the analyzer
func TestAnalyzeSQLDump(t *testing.T) {
	// Define the content needed to trigger all regexes
	sqlContent := `
-- Header info
INSERT INTO setting VALUES ('looker_version', '23.18.25');

-- Table 1: Required, has charset
CREATE TABLE user (
  id int(11) unsigned NOT NULL AUTO_INCREMENT,
  name varchar(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table 2: Required, simple insert
CREATE TABLE dashboard (
  id int(11)
);
INSERT INTO dashboard VALUES (1);

-- Table 3: Not Required (should still count towards total)
CREATE TABLE look (
  id int(11)
);

-- Extended Insert Logic (Multiple values in one statement)
INSERT INTO user VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
`

	t.Run("Scenario: Happy Path (Plain SQL)", func(t *testing.T) {
		// 1. Create a real file on disk
		tmpFile := filepath.Join(t.TempDir(), "dump.sql")
		err := os.WriteFile(tmpFile, []byte(sqlContent), 0644)
		require.NoError(t, err)

		// 2. Define expectations
		requiredTables := []string{"user", "dashboard"}

		// 3. Run Analysis
		res, err := validator.AnalyzeSQLDump(tmpFile, requiredTables)
		require.NoError(t, err)

		// 4. Assertions
		assert.Equal(t, "23.18.25", res.LookerVersion, "Should extract Looker version")
		assert.Equal(t, 3, res.TotalTableCount, "Should count 'user', 'dashboard', and 'look'")
		assert.True(t, res.HasExtendedInserts, "Should detect multi-value INSERT")
		assert.Empty(t, res.MissingTables, "All required tables are present")

		// Check Charsets
		assert.True(t, res.DetectedCharsets["utf8mb4"], "Should detect utf8mb4 charset")
		assert.True(t, res.DetectedCollations["utf8mb4_unicode_ci"], "Should detect collation")
	})

	t.Run("Scenario: Gzipped File Support", func(t *testing.T) {
		// 1. Create .gz file
		gzPath := filepath.Join(t.TempDir(), "dump.sql.gz")
		file, err := os.Create(gzPath)
		require.NoError(t, err)
		defer file.Close()

		gw := gzip.NewWriter(file)
		_, err = gw.Write([]byte(sqlContent))
		require.NoError(t, err)
		gw.Close() // Must close to flush data

		// 2. Run Analysis
		res, err := validator.AnalyzeSQLDump(gzPath, []string{"user"})
		require.NoError(t, err)

		// 3. Assertions
		assert.Equal(t, "23.18.25", res.LookerVersion)
		assert.Equal(t, 3, res.TotalTableCount)
	})

	t.Run("Scenario: Missing Tables", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "partial.sql")
		content := `CREATE TABLE user (id int);`
		err := os.WriteFile(tmpFile, []byte(content), 0644)
		require.NoError(t, err)

		// We ask for 'user' AND 'dashboard', but file only has 'user'
		res, err := validator.AnalyzeSQLDump(tmpFile, []string{"user", "dashboard"})
		require.NoError(t, err)

		assert.Contains(t, res.MissingTables, "dashboard")
		assert.NotContains(t, res.MissingTables, "user")
		assert.Equal(t, 1, res.TotalTableCount)
	})

	t.Run("Scenario: Regex Edge Cases", func(t *testing.T) {
		// Test variations in spacing/quoting
		complexContent := `
			INSERT INTO setting VALUES ("looker_version", "24.0.0");
			create table mixed_case_table (id int);
			DEFAULT CHARSET=latin1
		`
		tmpFile := filepath.Join(t.TempDir(), "edge.sql")
		err := os.WriteFile(tmpFile, []byte(complexContent), 0644)
		require.NoError(t, err)

		res, err := validator.AnalyzeSQLDump(tmpFile, []string{"mixed_case_table"})
		require.NoError(t, err)

		assert.Equal(t, "24.0.0", res.LookerVersion, "Should handle double quotes")
		assert.Equal(t, 1, res.TotalTableCount, "Should handle lowercase create table")
		assert.True(t, res.DetectedCharsets["latin1"], "Should detect latin1")
	})

	t.Run("Scenario: File Not Found", func(t *testing.T) {
		_, err := validator.AnalyzeSQLDump("non_existent_file.sql", nil)
		assert.Error(t, err)
	})
}
