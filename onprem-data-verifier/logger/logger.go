package logger

import (
	"fmt"
	"os"
)

// ANSI Color Codes (Only used ones)
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// Step prints a major section header: ">> [1/5] Checking Workspace..."
func Step(current, total int, message string) {
	// Format: >> [1/5] Checking Workspace (Cyan and Bold)
	fmt.Printf("\n%s%s>> [%d/%d] %s%s\n", Bold, Cyan, current, total, message, Reset)
}

// Success prints: "   [OK] Message" (Green)
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("   %s[OK]%s %s\n", Green, Reset, msg)
}

// Warn prints: "   [WARN] Message" (Yellow)
func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("   %s[WARN]%s %s\n", Yellow, Reset, msg)
}

// Error prints: "   [FAIL] Message" (Red)
// Use this for individual check failures inside a step.
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("   %s[FAIL]%s %s\n", Red, Reset, msg)
}

// Info prints generic info indented: "   Message"
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("   %s\n", msg)
}

// Title prints the main header of the tool
func Title(message string) {
	fmt.Printf("\n%s=== %s ===%s\n", Bold, message, Reset)
}

// Fatal prints a big error block and exits.
// USE THIS FOR: System errors, Config errors, Panic situations.
func Fatal(err error) {
	fmt.Printf("\n%s%s[ERROR] FATAL SYSTEM ERROR%s\n", Bold, Red, Reset)
	fmt.Printf("%s%v%s\n", Red, err, Reset)
	os.Exit(2)
}

// Completion prints the big success block.
// It accepts primitive types to avoid importing the 'metadata' package.
func Completion(
	customerName, instanceID, generatedAt, lookerVer string,
	tableCount int,
	fsTotalBytes, dbTotalBytes int64,
	cmkStatus, cmkFormat string,
	duration float64,
) {
	fmt.Printf("\n%s%s[SUCCESS] VERIFICATION COMPLETE%s\n", Bold, Green, Reset)
	fmt.Println("--------------------------------------------------")

	// Basic Info
	fmt.Printf("Customer:       %s\n", customerName)
	fmt.Printf("Instance ID:    %s\n", instanceID)
	fmt.Printf("Generated At:   %s\n", generatedAt)
	fmt.Printf("Looker Version: %s\n", lookerVer)

	// Stats
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Table Count:    %d\n", tableCount)
	fmt.Printf("FS Total Size:  %s\n", formatBytes(fsTotalBytes))
	fmt.Printf("DB Total Size:  %s\n", formatBytes(dbTotalBytes))

	// CMK & Timing
	fmt.Println("--------------------------------------------------")
	fmt.Printf("CMK Status:     %s\n", cmkStatus)
	if cmkFormat != "" {
		fmt.Printf("CMK Format:     %s\n", cmkFormat)
	}
	fmt.Printf("Duration:       %.2fs\n", duration)
	fmt.Println("--------------------------------------------------")
}

// formatBytes converts raw bytes to human-readable strings (KB, MB, GB)
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
