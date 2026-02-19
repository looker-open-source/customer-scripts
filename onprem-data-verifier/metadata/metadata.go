package metadata

import (
	"encoding/json"
	"onprem-data-verifier/logger"
	"os"
	"path/filepath"
)

// Report is the final artifact attached to the bundle
type Report struct {
	CustomerName      string  `json:"customer_name"`
	InstanceID        string  `json:"instance_id"`
	GeneratedAt       string  `json:"generated_at"`
	FSTotalSizeBytes  int64   `json:"fs_total_size_bytes"`
	DBTotalSizeBytes  int64   `json:"db_total_size_bytes"`
	TableCount        int     `json:"table_count"`
	CmkStatus         string  `json:"cmk_status"`
	CmkFormat         string  `json:"cmk_format"`
	LookerVer         string  `json:"looker_version"`
	DurationInSeconds float64 `json:"duration_in_seconds"`
}

// ToJSON serializes the report to bytes
func (r *Report) ToJSON() ([]byte, error) {
	// key: using standard spaces for indentation
	return json.MarshalIndent(r, "", "  ")
}

// Save writes the report to a specific file path
func (r *Report) Save(reportPath string) error {
	// 1. Analyze the path
	dir := filepath.Dir(reportPath)
	filename := filepath.Base(reportPath)
	finalPath := reportPath

	// 2. Validate directory (if not current dir)
	if dir != "." {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.Warn("Directory '%s' does not exist. Saving '%s' to current directory instead.", dir, filename)
			finalPath = filename
		}
	}

	if finalPath != "metadata.json" && finalPath == reportPath {
		logger.Info("Saving report to the user provided output path: %s", finalPath)
	} else if finalPath == "metadata.json" {
		logger.Info("Saving report to the current directory: %s", finalPath)
	}

	// 4. Serialize and Write
	data, err := r.ToJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(finalPath, data, 0644)
}
