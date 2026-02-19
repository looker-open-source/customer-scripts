package cmd

import (
	"fmt"
	"os"

	"onprem-data-verifier/logger"
	"onprem-data-verifier/validator"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Flags
	backupDir    string
	customerName string
	luid         string
	outputFile   string

	// RootCmd represents the base command
	RootCmd = &cobra.Command{
		Use:   "onprem-data-verifier",
		Short: "Validates On-Premise Looker backups before migration",
		Long: `
			On-Prem Data Verifier
			=====================
			Validates integrity and schema of Looker On-Premise backups.
			
			Requires a workspace directory (--backupDir) and explicit paths to critical files.
			
			Example:
			  onprem-data-verifier \
				--backupDir ./workspace \
				--customerName lookersre-scotty-1 \
				--luid "u-12345-6789
				--output metadata.json"`,

		Run: func(cmd *cobra.Command, args []string) {
			// Initialize Orchestrator with the new flag variables
			orchestrator := validator.NewOrchestrator(backupDir, customerName, luid)

			report, err := orchestrator.Run()
			if err != nil {
				// Use the logger to print the Red Error Block and Exit
				logger.Fatal(err)
			}

			// Use the logger for the Green Success Block
			// Format the float as a string (e.g., "1.23s")
			logger.Completion(
				report.CustomerName,
				report.InstanceID,
				report.GeneratedAt,
				report.LookerVer,
				report.TableCount,
				report.FSTotalSizeBytes,
				report.DBTotalSizeBytes,
				report.CmkStatus,
				report.CmkFormat,
				report.DurationInSeconds,
			)

			// Save the report to the output file
			if err := report.Save(outputFile); err != nil {
				logger.Warn("Could not save report: %v", err)
			}
		},
	}
)

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		// Changed fmt.Println to logger.Error for consistency
		logger.Error("%v", err)
		os.Exit(1)
	}
}

func init() {
	// 1. Define Persistent Flags
	RootCmd.PersistentFlags().StringVarP(&backupDir, "backupDir", "b", "", "Backup Directory containing ALL backup files")
	RootCmd.PersistentFlags().StringVarP(&customerName, "customerName", "c", "", "Customer Name for the report")
	RootCmd.PersistentFlags().StringVarP(&luid, "luid", "l", "", "Looker User ID (LUID)")
	RootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "metadata.json", "Output file for the report")

	// 2. Mark ALL specific flags as REQUIRED
	requiredFlags := []string{"backupDir", "customerName", "luid"}
	for _, flag := range requiredFlags {
		if err := RootCmd.MarkPersistentFlagRequired(flag); err != nil {
			// Using fmt here is fine for initialization panics
			panic(fmt.Sprintf("Failed to mark flag required: %s - %v", flag, err))
		}
	}

	// 3. Bind Viper
	bindFlags := []string{"backupDir", "customerName", "luid", "output"}
	for _, flag := range bindFlags {
		if err := viper.BindPFlag(flag, RootCmd.PersistentFlags().Lookup(flag)); err != nil {
			panic(fmt.Sprintf("Failed to bind flag to viper: %s - %v", flag, err))
		}
	}
}
