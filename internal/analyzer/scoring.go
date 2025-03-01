package analyzer

import "github.com/PradyXd/smart-audit.git/pkg/models"

func CalculateSecurityScore(vulnerabilities []models.Vulnerability) float64 {
	baseScore := 100.0
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case models.High:
			baseScore -= 30
		case models.Medium:
			baseScore -= 15
		case models.Low:
			baseScore -= 5
		}
	}
	
	// Ensure score doesn't go below 0
	if baseScore < 0 {
		return 0
	}
	return baseScore
}