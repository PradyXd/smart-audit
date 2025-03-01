package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"github.com/PradyXd/smart-audit/pkg/models"
)

// ExportReport exports vulnerabilities to different formats
func ExportReport(vulnerabilities []models.Vulnerability, format string, outputPath string) error {
	switch format {
	case "json":
		return exportJSON(vulnerabilities, outputPath)
	case "csv":
		return exportCSV(vulnerabilities, outputPath)
	case "html":
		return exportHTML(vulnerabilities, outputPath)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

func exportJSON(vulnerabilities []models.Vulnerability, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(vulnerabilities)
}

func exportCSV(vulnerabilities []models.Vulnerability, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Type", "Severity", "Description", "Recommendation"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, vuln := range vulnerabilities {
		record := []string{
			vuln.Type,
			string(vuln.Severity),
			vuln.Description,
			vuln.Recommendation,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportHTML(vulnerabilities []models.Vulnerability, outputPath string) error {
	const htmlTemplate = `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Smart Contract Vulnerability Report</title>
		<style>
			body { font-family: Arial, sans-serif; }
			table { width: 100%; border-collapse: collapse; }
			th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
			.high { color: red; }
			.medium { color: orange; }
			.low { color: green; }
		</style>
	</head>
	<body>
		<h1>Smart Contract Vulnerability Report</h1>
		<table>
			<tr>
				<th>Type</th>
				<th>Severity</th>
				<th>Description</th>
				<th>Recommendation</th>
			</tr>
			{{range .}}
			<tr>
				<td>{{.Type}}</td>
				<td class="{{lower .Severity}}">{{.Severity}}</td>
				<td>{{.Description}}</td>
				<td>{{.Recommendation}}</td>
			</tr>
			{{end}}
		</table>
	</body>
	</html>
	`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": func(s models.Severity) string {
			return string(s)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, vulnerabilities)
}