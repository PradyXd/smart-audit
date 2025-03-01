package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"math"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"github.com/PradyXd/smart-audit/pkg/models"
)

// SecurityReport represents a comprehensive security analysis report
type SecurityReport struct {
	ContractPath      string
	Vulnerabilities   []models.Vulnerability
	AnalysisTimestamp time.Time
	SecurityScore     float64
}

// GenerateReport creates a detailed security report for a smart contract
func GenerateReport(vulnerabilities []models.Vulnerability, contractPath string) *SecurityReport {
	return &SecurityReport{
		ContractPath:      contractPath,
		Vulnerabilities:   vulnerabilities,
		AnalysisTimestamp: time.Now(),
		SecurityScore:     calculateSecurityScore(vulnerabilities),
	}
}

// calculateSecurityScore computes a comprehensive security rating
func calculateSecurityScore(vulnerabilities []models.Vulnerability) float64 {
	baseScore := 100.0
	severityWeights := map[models.Severity]float64{
		models.Critical: 40.0,
		models.High:     30.0,
		models.Medium:   15.0,
		models.Low:      5.0,
	}

	for _, vuln := range vulnerabilities {
		if weight, exists := severityWeights[vuln.Severity]; exists {
			baseScore -= weight
		}
	}

	return math.Max(0, baseScore)
}

// PrintReport displays a comprehensive and visually appealing security report
func (r *SecurityReport) PrintReport() {
	// Print Header
	printHeader("🔒 Smart Contract Security Analysis Report", r.ContractPath)

	// Print Security Score
	printSecurityScore(r.SecurityScore)

	// Print Vulnerability Table
	printVulnerabilityTable(r.Vulnerabilities)

	// Print Summary Statistics
	printVulnerabilitySummary(r.Vulnerabilities)

	// Print Timestamp
	printAnalysisTimestamp(r.AnalysisTimestamp)
}

func printHeader(title, path string) {
	color.Cyan("╔══════════════════════════════════════════════════╗")
	color.Cyan("║             %s             ║", title)
	color.Cyan("╚══════════════════════════════════════════════════╝")
	color.White("\nContract Path: %s", path)
}

func printSecurityScore(score float64) {
	scoreColor := color.GreenString
	switch {
	case score < 30:
		scoreColor = color.RedString
	case score < 60:
		scoreColor = color.YellowString
	}

	color.White("\n🎯 Security Score: %s/100", scoreColor("%.2f", score))
}

func printVulnerabilityTable(vulnerabilities []models.Vulnerability) {
	// Sort vulnerabilities by severity
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return vulnerabilities[i].Severity > vulnerabilities[j].Severity
	})

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "Severity", "Description", "Recommendation"})
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgMagentaColor},
	)
	table.SetColumnColor(
		tablewriter.Colors{tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.FgYellowColor},
		tablewriter.Colors{tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
	)

	for _, vuln := range vulnerabilities {
		table.Append([]string{
			vuln.Type,
			string(vuln.Severity),
			vuln.Description,
			vuln.Recommendation,
		})
	}

	fmt.Println("\n🚨 Detected Vulnerabilities:")
	table.Render()
}

func printVulnerabilitySummary(vulnerabilities []models.Vulnerability) {
	severityCounts := make(map[models.Severity]int)
	for _, vuln := range vulnerabilities {
		severityCounts[vuln.Severity]++
	}

	color.White("\n📊 Vulnerability Summary:")
	for severity, count := range severityCounts {
		severityColor := color.WhiteString
		switch severity {
		case models.Critical:
			severityColor = color.RedString
		case models.High:
			severityColor = color.MagentaString
		case models.Medium:
			severityColor = color.YellowString
		case models.Low:
			severityColor = color.BlueString
		}
		color.White("   %s Vulnerabilities: %s", severityColor(string(severity)), severityColor("%d", count))
	}
}

func printAnalysisTimestamp(timestamp time.Time) {
	color.White("\n⏰ Analysis Timestamp: %s", timestamp.Format(time.RFC1123))
}

// ExportReport allows saving the report to a file
func (r *SecurityReport) ExportReport(outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create report file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write report content
	var reportContent strings.Builder
	reportContent.WriteString(fmt.Sprintf("Smart Contract Security Report\n"))
	reportContent.WriteString(fmt.Sprintf("Contract Path: %s\n", r.ContractPath))
	reportContent.WriteString(fmt.Sprintf("Security Score: %.2f/100\n", r.SecurityScore))
	reportContent.WriteString(fmt.Sprintf("Analysis Timestamp: %s\n\n", r.AnalysisTimestamp.Format(time.RFC1123)))

	reportContent.WriteString("Vulnerabilities:\n")
	for _, vuln := range r.Vulnerabilities {
		reportContent.WriteString(fmt.Sprintf("- Type: %s\n", vuln.Type))
		reportContent.WriteString(fmt.Sprintf("  Severity: %s\n", vuln.Severity))
		reportContent.WriteString(fmt.Sprintf("  Description: %s\n", vuln.Description))
		reportContent.WriteString(fmt.Sprintf("  Recommendation: %s\n\n", vuln.Recommendation))
	}

	_, err = file.WriteString(reportContent.String())
	return err
}