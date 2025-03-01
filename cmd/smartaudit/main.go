package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PradyXd/smart-audit/pkg/analyzer"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "smartaudit",
		Short: "Smart Contract Security Audit Tool",
	}

	var verbose bool
	var aiKey string
	var outputFormat string
	var severityFilter string
	var maxDepth int
	var recursive bool
	var parallelProcessing bool
	var logFile string

	var analyzeCmd = &cobra.Command{
		Use:   "analyze [contract_path]",
		Short: "Perform detailed smart contract analysis",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			contractPath := args[0]

			analyzerWrapper := &analyzer.ContractAnalyzerWrapper{}

			analysisResult, err := analyzerWrapper.AnalyzeContract(contractPath)
			if err != nil {
				log.Fatalf("Analysis failed: %v", err)
			}

			// Filter vulnerabilities by severity if specified
			if severityFilter != "" {
				filteredVulns := []analyzer.Vulnerability{}
				for _, vuln := range analysisResult.Vulnerabilities {
					if strings.EqualFold(string(vuln.Severity), severityFilter) {
						filteredVulns = append(filteredVulns, vuln)
					}
				}
				analysisResult.Vulnerabilities = filteredVulns
			}

			// Output formatting
			switch outputFormat {
			case "json":
				jsonOutput, _ := json.MarshalIndent(analysisResult, "", "  ")
				fmt.Println(string(jsonOutput))
			case "markdown":
				printMarkdownReport(analysisResult)
			case "table":
				printColoredTableReport(analysisResult)
			default:
				printTableReport(analysisResult)
			}
		},
	}

	var deepAnalyzeCmd = &cobra.Command{
		Use:   "deep-analyze [contract_path]",
		Short: "Perform AI-enhanced deep contract analysis",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			contractPath := args[0]

			analyzerWrapper := &analyzer.ContractAnalyzerWrapper{}
			analysisResult, err := analyzerWrapper.DeepAnalyzeContract(contractPath, aiKey, maxDepth)
			if err != nil {
				log.Fatalf("Deep analysis failed: %v", err)
			}

			fmt.Println(" AI-Enhanced Deep Contract Analysis")
			printColoredTableReport(analysisResult)
		},
	}

	var batchAnalyzeCmd = &cobra.Command{
		Use:   "batch-analyze [directory_path]",
		Short: "Analyze multiple contracts in a directory",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			dirPath := args[0]

			analyzerWrapper := &analyzer.ContractAnalyzerWrapper{}
			results, err := analyzerWrapper.BatchAnalyzeContracts(dirPath, recursive, parallelProcessing)
			if err != nil {
				log.Fatalf("Batch analysis failed: %v", err)
			}

			if logFile != "" {
				saveResultsToLogFile(results, logFile)
			}

			var totalVulnerabilities int
			var averageSecurityScore float64

			for _, result := range results {
				fmt.Printf(" Contract: %s\n", result.ContractPath)
				printColoredTableReport(result)
				fmt.Println("---")

				totalVulnerabilities += len(result.Vulnerabilities)
				averageSecurityScore += result.SecurityScore
			}

			if len(results) > 0 {
				averageSecurityScore /= float64(len(results))
				fmt.Printf(" Batch Analysis Summary:\n")
				fmt.Printf("- Total Contracts Analyzed: %d\n", len(results))
				fmt.Printf("- Total Vulnerabilities: %d\n", totalVulnerabilities)
				fmt.Printf("- Average Security Score: %.2f/100\n", averageSecurityScore)
			}
		},
	}

	// Analyze command flags
	analyzeCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	analyzeCmd.Flags().StringVar(&outputFormat, "output-format", "table", "Output format (json, table, markdown)")
	analyzeCmd.Flags().StringVar(&severityFilter, "severity-filter", "", "Filter vulnerabilities by severity (low, medium, high)")

	// Deep analyze command flags
	deepAnalyzeCmd.Flags().StringVar(&aiKey, "ai-key", "", "OpenAI API key for advanced suggestions")
	deepAnalyzeCmd.Flags().IntVar(&maxDepth, "max-depth", 3, "Maximum analysis depth for complex contracts")

	// Batch analyze command flags
	batchAnalyzeCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Recursively analyze contracts in subdirectories")
	batchAnalyzeCmd.Flags().BoolVarP(&parallelProcessing, "parallel", "p", false, "Enable parallel processing of contracts")
	batchAnalyzeCmd.Flags().StringVarP(&logFile, "log-file", "l", "", "Save analysis results to a log file")

	rootCmd.AddCommand(analyzeCmd, deepAnalyzeCmd, batchAnalyzeCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func printColoredTableReport(result analyzer.AnalysisResult) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Contract", "Severity", "Vulnerability", "Description"})
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor},
	)

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	for _, vuln := range result.Vulnerabilities {
		severityColor := green
		if vuln.Severity == "HIGH" {
			severityColor = red
		} else if vuln.Severity == "MEDIUM" {
			severityColor = yellow
		}

		table.Append([]string{
			result.ContractPath,
			severityColor(vuln.Severity),
			vuln.Type,
			truncateDescription(vuln.Description, 100),
		})
	}

	table.Render()

	// Summary statistics
	totalVulns := len(result.Vulnerabilities)
	highVulns := countVulnerabilitiesBySeverity(result.Vulnerabilities, "HIGH")
	mediumVulns := countVulnerabilitiesBySeverity(result.Vulnerabilities, "MEDIUM")
	lowVulns := countVulnerabilitiesBySeverity(result.Vulnerabilities, "LOW")

	fmt.Println("\n📊 Vulnerability Summary:")
	fmt.Printf("🔴 High Risk: %d\n", highVulns)
	fmt.Printf("🟠 Medium Risk: %d\n", mediumVulns)
	fmt.Printf("🟢 Low Risk: %d\n", lowVulns)
	fmt.Printf("📝 Total Vulnerabilities: %d\n", totalVulns)
}

func countVulnerabilitiesBySeverity(vulnerabilities []analyzer.Vulnerability, severity string) int {
	count := 0
	for _, vuln := range vulnerabilities {
		if strings.EqualFold(string(vuln.Severity), severity) {
			count++
		}
	}
	return count
}

func printTableReport(result analyzer.AnalysisResult) {
	// Use text/tabwriter for aligned, minimalistic output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)

	fmt.Fprintf(w, " Contract:\t%s\n", result.ContractPath)
	fmt.Fprintf(w, " Security Score:\t%.2f/100\n", result.SecurityScore)
	fmt.Fprintf(w, " Vulnerabilities:\t%d\n\n", len(result.Vulnerabilities))

	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintln(w, "Type\tSeverity\tDescription")
		for _, vuln := range result.Vulnerabilities {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				vuln.Type,
				vuln.Severity,
				truncateDescription(vuln.Description, 50),
			)
		}
	}

	w.Flush()
}

func printMarkdownReport(result analyzer.AnalysisResult) {
	fmt.Printf("# Smart Contract Security Analysis: %s\n\n", result.ContractPath)
	fmt.Printf("## Security Overview\n")
	fmt.Printf("- **Security Score**: `%.2f/100`\n", result.SecurityScore)
	fmt.Printf("- **Total Vulnerabilities**: `%d`\n\n", len(result.Vulnerabilities))

	fmt.Println("## Vulnerability Details")
	for _, vuln := range result.Vulnerabilities {
		fmt.Printf("### %s Vulnerability\n", vuln.Type)
		fmt.Printf("- **Severity**: `%s`\n", vuln.Severity)
		fmt.Printf("- **Description**: %s\n", vuln.Description)
		fmt.Printf("- **Recommendation**: %s\n\n", vuln.Recommendation)
	}
}

func saveResultsToLogFile(results []analyzer.AnalysisResult, logFile string) error {
	if len(results) == 0 {
		return fmt.Errorf("no results to save")
	}

	// Create log file
	file, err := os.Create(logFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Smart Audit Analysis Log\n")
	fmt.Fprintf(file, "## Batch Analysis Report\n")
	fmt.Fprintf(file, "- Date: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "- Total Contracts: %d\n\n", len(results))

	// Tabulate results
	w := tabwriter.NewWriter(file, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "Contract Path\tVulnerabilities\tSecurity Score\tHighest Severity")

	for _, result := range results {
		highestSeverity := getHighestSeverity(result.Vulnerabilities)
		fmt.Fprintf(w, "%s\t%d\t%.2f/100\t%s\n",
			result.ContractPath,
			len(result.Vulnerabilities),
			result.SecurityScore,
			highestSeverity,
		)
	}
	w.Flush()

	return nil
}

func getHighestSeverity(vulnerabilities []analyzer.Vulnerability) string {
	severityOrder := map[analyzer.Severity]int{
		analyzer.Critical: 4,
		analyzer.High:     3,
		analyzer.Medium:   2,
		analyzer.Low:      1,
	}

	highestSeverity := analyzer.Low
	for _, vuln := range vulnerabilities {
		if severityOrder[vuln.Severity] > severityOrder[highestSeverity] {
			highestSeverity = vuln.Severity
		}
	}
	return string(highestSeverity)
}

func truncateDescription(desc string, maxLen int) string {
	if len(desc) <= maxLen {
		return desc
	}
	return desc[:maxLen] + "..."
}
