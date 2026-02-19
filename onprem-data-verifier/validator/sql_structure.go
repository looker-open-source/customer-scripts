package validator

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Regex patterns (Pre-compiled for performance)
var (
	// Matches: 'looker_version', "23.18.0"
	versionRegex = regexp.MustCompile(`['"]looker_version['"]\s*,\s*['"](?:\\")?([0-9.]+)(?:\\")?['"]`)

	// Matches: CREATE TABLE `user`
	tableRegex = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+[` + "`" + `]?(\w+)[` + "`" + `]?`)

	// Matches: INSERT INTO ... VALUES (...), (...)
	extendedInsertRegex = regexp.MustCompile(`(?i)INSERT\s+INTO.*VALUES\s*\(.*\)\s*,\s*\(.*\)`)

	// Matches: DEFAULT CHARSET=utf8mb4
	charsetRegex = regexp.MustCompile(`(?i)DEFAULT\s+CHARSET\s*=\s*([a-z0-9_]+)`)

	// Matches: COLLATE=utf8mb4_general_ci
	collateRegex = regexp.MustCompile(`(?i)COLLATE\s*=\s*([a-z0-9_]+)`)
)

// SQLAnalysisResult holds all data extracted from the single pass
type SQLAnalysisResult struct {
	LookerVersion      string
	HasExtendedInserts bool
	MissingTables      []string
	TotalTableCount    int

	// Sets of detected encodings (e.g., "utf8mb4": true, "latin1": true)
	DetectedCharsets   map[string]bool
	DetectedCollations map[string]bool
}

// AnalyzeSQLDump scans the file ONCE and gathers all metrics
func AnalyzeSQLDump(filePath string, requiredTables []string) (*SQLAnalysisResult, error) {
	// 1. Open the stream
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var scanner *bufio.Scanner
	var gzReader *gzip.Reader

	if strings.HasSuffix(filePath, ".gz") {
		gzReader, err = gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		scanner = bufio.NewScanner(gzReader)
	} else {
		scanner = bufio.NewScanner(file)
	}

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	// 2. Initialize State
	result := &SQLAnalysisResult{
		LookerVersion:      "",
		HasExtendedInserts: false,
		DetectedCharsets:   make(map[string]bool),
		DetectedCollations: make(map[string]bool),
		TotalTableCount:    0,
	}

	requiredMap := make(map[string]bool)
	foundMap := make(map[string]bool)
	for _, t := range requiredTables {
		requiredMap[t] = true
	}

	// 3. Single Pass Loop
	for scanner.Scan() {
		line := scanner.Text()

		// A. Version
		if result.LookerVersion == "" && strings.Contains(line, "looker_version") {
			matches := versionRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				result.LookerVersion = matches[1]
			}
		}

		// B. Create Table
		// FIX: Use case-insensitive prefix check.
		// strings.Contains(line, "CREATE TABLE") failed on lowercase "create table".
		// We check for "CREATE" to capture "CREATE TABLE", "create table", or "CREATE   TABLE".
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 6 && strings.EqualFold(trimmed[:6], "CREATE") {
			matches := tableRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				// We found A table. Increment the total count.
				result.TotalTableCount++

				// Check if it's one of the required ones
				tableName := matches[1]
				if requiredMap[tableName] {
					foundMap[tableName] = true
				}
			}
		}

		// C. Extended Inserts
		// (Logic remains the same, but using EqualFold is safer here too if "insert" is lowercase)
		if !result.HasExtendedInserts && len(trimmed) >= 6 && strings.EqualFold(trimmed[:6], "INSERT") {
			if extendedInsertRegex.MatchString(line) {
				result.HasExtendedInserts = true
			}
		}

		// D. Charset & Collation
		if strings.Contains(line, "DEFAULT CHARSET") || strings.Contains(line, "COLLATE") {
			if match := charsetRegex.FindStringSubmatch(line); len(match) > 1 {
				result.DetectedCharsets[match[1]] = true
			}
			if match := collateRegex.FindStringSubmatch(line); len(match) > 1 {
				result.DetectedCollations[match[1]] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SQL stream: %w", err)
	}

	// 4. Calculate Missing Tables
	for _, req := range requiredTables {
		if !foundMap[req] {
			result.MissingTables = append(result.MissingTables, req)
		}
	}

	return result, nil
}

// IsLookerVersionSupported checks the version string against config (Helper)
func IsLookerVersionSupported(version string, supportedList []string) bool {
	for _, sup := range supportedList {
		if version == sup || strings.HasPrefix(version, sup+".") {
			return true
		}
	}
	return false
}
