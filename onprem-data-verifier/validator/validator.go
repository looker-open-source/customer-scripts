package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"onprem-data-verifier/logger"
	"onprem-data-verifier/metadata"
)

// BackupPaths holds the absolute paths to all required files
type BackupPaths struct {
	EncryptedSQL string
	EncryptedFS  string
	EncryptedCMK string
	ManifestMD5  string
	DecryptedSQL string
	DecryptedFS  string
	DecryptedCMK string
}

// Orchestrator manages the validation process
type Orchestrator struct {
	DataDir      string
	CustomerName string
	LUID         string
	Config       ValidationConfig
	Paths        BackupPaths

	// State
	Report    metadata.Report
	StartTime string
}

// NewOrchestrator creates a new instance
func NewOrchestrator(dataDir, customerName, luid string) *Orchestrator {
	return &Orchestrator{
		DataDir:      dataDir,
		CustomerName: customerName,
		LUID:         luid,
		Config:       GetDefaultConfig(),
		Paths: BackupPaths{
			EncryptedSQL: filepath.Join(dataDir, fmt.Sprintf("%s_looker_db_backup.sql.gz.enc", customerName)),
			EncryptedFS:  filepath.Join(dataDir, fmt.Sprintf("%s_looker_fs_backup.tar.gz.enc", customerName)),
			EncryptedCMK: filepath.Join(dataDir, fmt.Sprintf("%s_looker_cmk_key.enc", customerName)),
			ManifestMD5:  filepath.Join(dataDir, fmt.Sprintf("%s_backup.md5", customerName)),
			DecryptedSQL: filepath.Join(dataDir, fmt.Sprintf("%s_looker_db_backup.sql.gz", customerName)),
			DecryptedFS:  filepath.Join(dataDir, fmt.Sprintf("%s_looker_fs_backup.tar.gz", customerName)),
			DecryptedCMK: filepath.Join(dataDir, fmt.Sprintf("%s_looker_cmk_key", customerName)),
		},
	}
}

// Run executes all checks and returns the final report
func (o *Orchestrator) Run() (*metadata.Report, error) {

	startTimeOfTheProgram := time.Now()
	const totalSteps = 6
	currentStep := 1

	logger.Title("Looker On-Prem Verification Pipeline")

	o.StartTime = time.Now().UTC().Format(time.RFC3339)

	o.Report = metadata.Report{
		CustomerName: o.CustomerName,
		InstanceID:   o.LUID,
		GeneratedAt:  o.StartTime,
		TableCount:   0,
	}

	// STEP 1: Workspace
	logger.Step(currentStep, totalSteps, "Checking Workspace Structure")
	logger.Info("Directory: %s", o.DataDir)
	if err := o.verifyWorkspace(); err != nil {
		return nil, err
	}
	logger.Success("Workspace structure verified")
	currentStep++

	// STEP 2: Integrity
	logger.Step(currentStep, totalSteps, "Verifying MD5 Checksums")
	if err := o.verifyIntegrity(); err != nil {
		return nil, err
	}
	logger.Success("All files match their checksums")
	currentStep++

	// STEP 3: GPG Keys
	logger.Step(currentStep, totalSteps, "Resolving Security Keys")
	if err := o.verifyGPGKeys(); err != nil {
		return nil, err
	}
	currentStep++

	// STEP 4: Database
	logger.Step(currentStep, totalSteps, fmt.Sprintf("Analyzing Database: %s", filepath.Base(o.Paths.DecryptedSQL)))
	if err := o.validateDatabase(o.Paths.DecryptedSQL); err != nil {
		return nil, err
	}
	currentStep++

	// STEP 5: CMK
	logger.Step(currentStep, totalSteps, "Validating Customer Master Key (CMK)")
	if err := o.validateCMK(o.Paths.DecryptedCMK); err != nil {
		return nil, err
	}
	currentStep++

	// STEP 6: FileSystem
	logger.Step(currentStep, totalSteps, fmt.Sprintf("Analyzing FileSystem: %s", filepath.Base(o.Paths.DecryptedFS)))
	o.validateFileSystem(o.Paths.DecryptedFS)
	currentStep++

	// Finalize Report Duration
	o.Report.DurationInSeconds = time.Since(startTimeOfTheProgram).Seconds()

	return &o.Report, nil
}

// ---------------------------------------------------------------------
// Validation Methods (Mutate o.Report)
// ---------------------------------------------------------------------

func (o *Orchestrator) validateDatabase(sqlPath string) error {
	// 1. Check File Size
	info, err := os.Stat(sqlPath)
	if err != nil {
		return fmt.Errorf("could not access SQL file: %w", err)
	}
	o.Report.DBTotalSizeBytes = info.Size()

	// 2. Run Single-Pass Analysis
	stats, err := AnalyzeSQLDump(sqlPath, o.Config.TablesToCheck)
	if err != nil {
		logger.Error("Failed to analyze SQL dump: %v", err)
		return err
	}

	// 3. Version Check
	if stats.LookerVersion == "" {
		logger.Warn("Could not extract Looker version")
		o.Report.LookerVer = "Unknown"
	} else {
		o.Report.LookerVer = stats.LookerVersion
		if IsLookerVersionSupported(stats.LookerVersion, o.Config.SupportedVersions) {
			logger.Success("Version %s is supported", stats.LookerVersion)
		} else {
			logger.Error("Version %s is NOT supported", stats.LookerVersion)
			return fmt.Errorf("unsupported Looker version: %s", stats.LookerVersion)
		}
	}

	// 4. Charset Check
	validCharset := true
	for charset := range stats.DetectedCharsets {
		if charset != "utf8mb4" {
			logger.Error("Found invalid charset: %s (Looker requires utf8mb4)", charset)
			validCharset = false
		}
	}
	if !validCharset {
		return fmt.Errorf("invalid database charset detected")
	}
	// Print OK if we found at least one valid charset
	if len(stats.DetectedCharsets) > 0 {
		logger.Success("Database Charset: utf8mb4")
	}

	// 5. Extended Inserts Check
	if !stats.HasExtendedInserts {
		logger.Error("SQL dump does not use Extended Inserts (Performance Risk)")
		return fmt.Errorf("SQL dump missing extended inserts")
	}
	logger.Success("Extended Inserts detected")

	if len(stats.MissingTables) > 0 {
		logger.Error("Missing critical tables: %v", stats.MissingTables)
		return fmt.Errorf("missing tables: %v", stats.MissingTables)
	}
	logger.Success("Critical tables verified: %v", o.Config.TablesToCheck)

	// FIX: Use the actual total count found in the SQL dump
	o.Report.TableCount = stats.TotalTableCount

	return nil
}

func (o *Orchestrator) validateCMK(cmkPath string) error {
	isValid, format, err := ValidateCMK(cmkPath)
	if err != nil {
		o.Report.CmkStatus = "Corrupt"
		o.Report.CmkFormat = "Unknown"
		logger.Error("CMK validation failed: %v", err)
		return err
	}

	if isValid {
		o.Report.CmkStatus = "Valid"
		o.Report.CmkFormat = format
		logger.Success("CMK is valid %s", format)
		return nil
	}

	// Execution will never reach here but we need to add a return to keep compiler happy
	o.Report.CmkStatus = "Invalid"
	return fmt.Errorf("CMK is invalid")
}

func (o *Orchestrator) validateFileSystem(fsPath string) {
	// Just capturing stats for the report, no strict failure condition here yet
	info, err := os.Stat(fsPath)
	if err == nil {
		o.Report.FSTotalSizeBytes = info.Size()
		// Optional: logger.Info("Archive Size: %.2f GB", float64(info.Size())/1024/1024/1024)
	} else {
		logger.Warn("Could not stat filesystem archive: %v", err)
	}
}

// ---------------------------------------------------------------------
// Structural Checks
// ---------------------------------------------------------------------

func (o *Orchestrator) verifyWorkspace() error {
	requiredFiles := []string{
		o.Paths.EncryptedSQL, o.Paths.EncryptedFS, o.Paths.EncryptedCMK, o.Paths.ManifestMD5,
		o.Paths.DecryptedSQL, o.Paths.DecryptedFS, o.Paths.DecryptedCMK,
	}

	missing := []string{}
	for _, path := range requiredFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			missing = append(missing, filepath.Base(path))
		}
	}

	if len(missing) > 0 {
		logger.Error("The following expected files are missing:")
		for _, f := range missing {
			logger.Info("      - %s", f)
		}
		return fmt.Errorf("workspace structure is invalid (missing %d files)", len(missing))
	}

	return nil
}

func (o *Orchestrator) verifyIntegrity() error {
	// Parse Manifest
	checksums, err := ParseMD5Manifest(o.Paths.ManifestMD5)
	if err != nil {
		return fmt.Errorf("failed to parse MD5 manifest: %w", err)
	}

	// Check every file listed in the manifest
	for filename, expectedHash := range checksums {
		valid, err := VerifyFile(o.DataDir, filename, expectedHash)
		if err != nil {
			logger.Warn("Could not verify %s: %v", filename, err)
			continue
		}

		if !valid {
			logger.Error("%s hash mismatch!", filename)
			return fmt.Errorf("integrity check failed for %s", filename)
		}

		logger.Success("%s hash verified", filename)
	}

	return nil
}

// ---------------------------------------------------------------------
// Phase 2: GPG Security Check
// ---------------------------------------------------------------------
func (o *Orchestrator) verifyGPGKeys() error {
	recipientEmail := fmt.Sprintf("looker-devops+migration-%s@google.com", o.LUID)
	logger.Info("Expected Recipient: %s", recipientEmail)

	targetKeyIDs, err := GetKeyIDsFromEmail(recipientEmail)
	if err != nil {
		logger.Error("Could not find Public Key in local GPG keyring")
		return err
	}

	logger.Success("Found Valid Key IDs: %v", targetKeyIDs)

	encryptedFiles := []string{
		o.Paths.EncryptedSQL,
		o.Paths.EncryptedFS,
		o.Paths.EncryptedCMK,
	}

	for _, path := range encryptedFiles {
		filename := filepath.Base(path)

		valid, err := VerifyRecipient(path, targetKeyIDs)
		if err != nil {
			logger.Error("%s: Error reading headers: %v", filename, err)
			return fmt.Errorf("GPG check error for %s", filename)
		}

		if valid {
			logger.Success("%s is encrypted correctly", filename)
		} else {
			logger.Error("%s: Key ID mismatch! (Expected one of %v)", filename, targetKeyIDs)
			return fmt.Errorf("recipient mismatch for %s", filename)
		}
	}
	return nil
}
