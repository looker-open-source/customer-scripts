package validator

// ValidationConfig represents the rules defined in config.yaml
type ValidationConfig struct {
	SizeThresholdGB   int
	SupportedVersions []string
	TablesToCheck     []string
}

// GetDefaultConfig returns the hardcoded validation policies
func GetDefaultConfig() ValidationConfig {
	return ValidationConfig{
		SizeThresholdGB: 50,
		SupportedVersions: []string{
			"25.20", "25.18", "25.16", "25.14", "25.12", "25.10", "25.8", "25.6", "25.4", "25.2", "25.0",
			"24.20", "24.18", "24.16", "24.14", "24.12", "24.10", "24.8", "24.6", "24.4", "24.2", "24.0",
			"23.20", "23.18", "23.16", "23.14", "23.12", "23.10", "23.8", "23.6", "23.4", "23.0",
			"22.18",
		},
		TablesToCheck: []string{"user", "dashboard", "db_connection"}, // Add more as needed
	}
}
