package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// AnalysisResult represents the comprehensive result of a contract analysis
type AnalysisResult struct {
	ContractPath    string
	Vulnerabilities []Vulnerability
	SecurityScore   float64
}

// ContractAnalyzer defines the interface for contract vulnerability analysis
type ContractAnalyzer interface {
	AnalyzeContract(path string) (AnalysisResult, error)
	DeepAnalyzeContract(path string, aiKey string, maxDepth int) (AnalysisResult, error)
	BatchAnalyzeContracts(dirPath string, recursive bool, parallel bool) ([]AnalysisResult, error)
}

// ContractAnalyzerWrapper provides a comprehensive contract analysis implementation
type ContractAnalyzerWrapper struct{}

// AnalyzeContract performs a multi-threaded, comprehensive vulnerability analysis
func (w *ContractAnalyzerWrapper) AnalyzeContract(path string) (AnalysisResult, error) {
	// Read contract content
	content, err := os.ReadFile(path)
	if err != nil {
		return AnalysisResult{}, err
	}

	contractStr := string(content)
	vulnerabilities := []Vulnerability{}

	// Define vulnerability checks with their descriptions
	checks := []struct {
		check       func(string) []Vulnerability
		description string
	}{
		{checkUnsafeTransfer, "Token Transfer Security"},
		{checkTimestampManipulation, "Timestamp Dependence"},
		{checkReentrancy, "Reentrancy Vulnerability"},
		{checkAccessControl, "Access Control Weakness"},
		{checkSelfDestruct, "Contract Destruction Risk"},
		{checkDelegateCall, "Delegate Call Vulnerability"},
		{checkMathOperations, "Mathematical Vulnerability"},
		{checkExternalCalls, "External Call Risks"},
	}

	// Use concurrent checks for improved performance
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(len(checks))

	for _, check := range checks {
		go func(checkFunc func(string) []Vulnerability) {
			defer wg.Done()
			vulns := checkFunc(contractStr)
			mu.Lock()
			vulnerabilities = append(vulnerabilities, vulns...)
			mu.Unlock()
		}(check.check)
	}

	wg.Wait()

	// Calculate security score
	securityScore := calculateSecurityScore(vulnerabilities)

	return AnalysisResult{
		ContractPath:    path,
		Vulnerabilities: vulnerabilities,
		SecurityScore:   securityScore,
	}, nil
}

// DeepAnalyzeContract performs an advanced AI-enhanced vulnerability analysis
func (w *ContractAnalyzerWrapper) DeepAnalyzeContract(path string, aiKey string, maxDepth int) (AnalysisResult, error) {
	// Initial standard analysis
	baseResult, err := w.AnalyzeContract(path)
	if err != nil {
		return AnalysisResult{}, err
	}

	// Simulate AI-enhanced analysis (replace with actual AI integration)
	if aiKey != "" {
		// Placeholder for AI vulnerability detection
		aiVulnerabilities := w.performAIVulnerabilityDetection(baseResult.ContractPath, aiKey, maxDepth)
		baseResult.Vulnerabilities = append(baseResult.Vulnerabilities, aiVulnerabilities...)
		baseResult.SecurityScore = calculateSecurityScore(baseResult.Vulnerabilities)
	}

	return baseResult, nil
}

// BatchAnalyzeContracts performs analysis on multiple contracts in a directory
func (w *ContractAnalyzerWrapper) BatchAnalyzeContracts(dirPath string, recursive bool, parallel bool) ([]AnalysisResult, error) {
	var results []AnalysisResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Find contract files
	contractFiles, err := findContractFiles(dirPath, recursive)
	if err != nil {
		return nil, err
	}

	// Analyze contracts
	if parallel {
		for _, contractPath := range contractFiles {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				result, err := w.AnalyzeContract(path)
				if err == nil {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}(contractPath)
		}
		wg.Wait()
	} else {
		for _, contractPath := range contractFiles {
			result, err := w.AnalyzeContract(contractPath)
			if err == nil {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// Helper function to find Solidity contract files
func findContractFiles(dirPath string, recursive bool) ([]string, error) {
	var contractFiles []string

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".sol") {
			contractFiles = append(contractFiles, path)
		}
		return nil
	}

	if recursive {
		err := filepath.Walk(dirPath, walkFunc)
		if err != nil {
			return nil, err
		}
	} else {
		files, err := os.ReadDir(dirPath)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if !file.IsDir() && filepath.Ext(file.Name()) == ".sol" {
				contractFiles = append(contractFiles, filepath.Join(dirPath, file.Name()))
			}
		}
	}

	return contractFiles, nil
}

// performAIVulnerabilityDetection simulates AI-enhanced vulnerability detection
func (w *ContractAnalyzerWrapper) performAIVulnerabilityDetection(contractPath, aiKey string, maxDepth int) []Vulnerability {
	// Validate inputs
	if contractPath == "" {
		return nil
	}

	// Simulate AI-powered analysis based on contract path and max depth
	aiVulnerabilities := []Vulnerability{}

	// Basic AI simulation based on contract path characteristics
	pathVulnerabilities := []struct {
		pathPattern       string
		vulnerabilityType string
		severity          Severity
		description       string
		recommendation    string
	}{
		{
			pathPattern:       "lending",
			vulnerabilityType: "AI-Enhanced Lending Risk",
			severity:          High,
			description:       "Potential high-risk lending contract detected by AI analysis",
			recommendation:    "Conduct thorough manual review, verify collateralization mechanisms",
		},
		{
			pathPattern:       "defi",
			vulnerabilityType: "AI-Enhanced DeFi Risk",
			severity:          Medium,
			description:       "Potential DeFi contract complexity detected",
			recommendation:    "Review complex financial logic, verify mathematical operations",
		},
	}

	for _, pattern := range pathVulnerabilities {
		if strings.Contains(strings.ToLower(contractPath), pattern.pathPattern) {
			aiVulnerabilities = append(aiVulnerabilities, Vulnerability{
				Type:           pattern.vulnerabilityType,
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	// Depth-based vulnerability simulation
	if maxDepth > 3 {
		aiVulnerabilities = append(aiVulnerabilities, Vulnerability{
			Type:           "AI-Enhanced Complexity Warning",
			Description:    "Contract analysis depth exceeds standard complexity threshold",
			Severity:       Medium,
			Recommendation: "Consider breaking down complex contract logic",
		})
	}

	// Simulate API key validation (placeholder)
	if aiKey == "" {
		aiVulnerabilities = append(aiVulnerabilities, Vulnerability{
			Type:           "AI Integration Warning",
			Description:    "No AI analysis key provided, using limited AI capabilities",
			Severity:       Low,
			Recommendation: "Provide a valid AI analysis API key for enhanced detection",
		})
	}

	return aiVulnerabilities
}

// Generic vulnerability detection helper function
func detectVulnerabilities[T any](contract string, patterns []T) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, pattern := range patterns {
		// Use type switch to handle different pattern struct types
		switch p := any(pattern).(type) {
		case struct {
			pattern        string
			context        []string
			severity       Severity
			description    string
			recommendation string
		}:
			if strings.Contains(contract, p.pattern) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:           extractVulnerabilityType(p.pattern),
					Description:    p.description,
					Severity:       p.severity,
					Recommendation: p.recommendation,
				})
			}
		case struct {
			pattern        string
			severity       Severity
			description    string
			recommendation string
		}:
			if strings.Contains(contract, p.pattern) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:           extractVulnerabilityType(p.pattern),
					Description:    p.description,
					Severity:       p.severity,
					Recommendation: p.recommendation,
				})
			}
		}
	}

	return vulnerabilities
}

// Helper function to extract vulnerability type from pattern
func extractVulnerabilityType(pattern string) string {
	switch {
	case strings.Contains(pattern, "transfer"):
		return "Unsafe Transfer"
	case strings.Contains(pattern, "timestamp") || strings.Contains(pattern, "now"):
		return "Timestamp Manipulation"
	case strings.Contains(pattern, "reentrancy") || strings.Contains(pattern, "external call"):
		return "Reentrancy"
	default:
		return "Unknown Vulnerability"
	}
}

func checkUnsafeTransfer(contract string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	transferPatterns := []struct {
		pattern        string
		context        []string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "transfer(",
			context:        []string{"msg.sender", "balance"},
			severity:       High,
			description:    "Potential unsafe token transfer mechanism without comprehensive checks",
			recommendation: "Use SafeERC20 library, implement comprehensive transfer validation, add explicit balance checks, use pull-over-push payment strategy",
		},
		{
			pattern:        "call.value",
			context:        []string{"external call", "transfer"},
			severity:       Critical,
			description:    "Vulnerable low-level value transfer mechanism with potential reentrancy risk",
			recommendation: "Use modern transfer patterns, implement checks-effects-interactions pattern, add reentrancy guards",
		},
	}

	for _, pattern := range transferPatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           extractVulnerabilityType(pattern.pattern),
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}
	return vulnerabilities
}

func checkTimestampManipulation(contract string) []Vulnerability {
	timestampPatterns := []struct {
		pattern        string
		context        []string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "block.timestamp",
			context:        []string{"critical logic", "randomness"},
			severity:       Medium,
			description:    "Contract relies on block.timestamp which can be manipulated by miners",
			recommendation: "Use external oracles like Chainlink VRF, implement time-window tolerances, avoid critical logic based on timestamps",
		},
		{
			pattern:        "now",
			context:        []string{"deprecated", "solidity version"},
			severity:       Low,
			description:    "Deprecated 'now' keyword indicates potential outdated practices",
			recommendation: "Replace 'now' with block.timestamp, upgrade Solidity compiler, review time-dependent logic",
		},
	}

	return detectVulnerabilities(contract, timestampPatterns)
}

func checkReentrancy(contract string) []Vulnerability {
	reentrancyPatterns := []struct {
		pattern        string
		context        []string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "reentrancy",
			context:        []string{"external call", "state change"},
			severity:       High,
			description:    "Potential reentrancy vulnerability detected",
			recommendation: "Implement checks-effects-interactions pattern, use ReentrancyGuard, update state before external calls",
		},
		{
			pattern:        "external call before state change",
			context:        []string{"transfer", "send", "call"},
			severity:       High,
			description:    "Potential reentrancy vulnerability with external calls and state mutations",
			recommendation: "Implement checks-effects-interactions pattern, use ReentrancyGuard from OpenZeppelin, update state before external calls",
		},
		{
			pattern:        "payable(msg.sender).transfer(",
			context:        []string{"balance update", "withdrawal"},
			severity:       High,
			description:    "Direct transfer without reentrancy protection in critical financial functions",
			recommendation: "Use pull-payment pattern, implement reentrancy guards, follow CEI (Checks-Effects-Interactions) pattern",
		},
		{
			pattern:        "call.value",
			context:        []string{"external call", "transfer"},
			severity:       High,
			description:    "Low-level call with value transfer potentially vulnerable to reentrancy",
			recommendation: "Use modern transfer patterns, implement reentrancy guards, follow checks-effects-interactions pattern",
		},
	}

	return detectVulnerabilities(contract, reentrancyPatterns)
}

func checkAccessControl(contract string) []Vulnerability {
	var vulnerabilities []Vulnerability

	accessControlPatterns := []struct {
		pattern        string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "function withdraw",
			severity:       High,
			description:    "Potential weak access control for critical functions",
			recommendation: "Implement strict access control modifiers like onlyOwner, use role-based access control",
		},
	}

	for _, pattern := range accessControlPatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "Access Control Weakness",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	return vulnerabilities
}

func checkSelfDestruct(contract string) []Vulnerability {
	var vulnerabilities []Vulnerability

	destructPatterns := []struct {
		pattern        string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "selfdestruct(",
			severity:       Medium,
			description:    "Contract contains self-destruct mechanism which can permanently disable the contract",
			recommendation: "Remove or strictly control self-destruct functionality, implement multi-signature destruction",
		},
	}

	for _, pattern := range destructPatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "Contract Destruction Risk",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	return vulnerabilities
}

func checkDelegateCall(contract string) []Vulnerability {
	var vulnerabilities []Vulnerability

	delegatePatterns := []struct {
		pattern        string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "delegatecall(",
			severity:       High,
			description:    "Potential security risk with delegatecall that can modify contract state",
			recommendation: "Avoid using delegatecall, if necessary implement strict validation and use proxy patterns",
		},
	}

	for _, pattern := range delegatePatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "Delegate Call Vulnerability",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	return vulnerabilities
}

func checkMathOperations(contract string) []Vulnerability {
	var vulnerabilities []Vulnerability

	mathPatterns := []struct {
		pattern        string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "unchecked",
			severity:       Medium,
			description:    "Potential integer overflow or underflow risk",
			recommendation: "Use SafeMath library or Solidity 0.8+ built-in overflow checks",
		},
	}

	for _, pattern := range mathPatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "Mathematical Vulnerability",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	return vulnerabilities
}

func checkExternalCalls(contract string) []Vulnerability {
	var vulnerabilities []Vulnerability

	externalCallPatterns := []struct {
		pattern        string
		severity       Severity
		description    string
		recommendation string
	}{
		{
			pattern:        "external call",
			severity:       Medium,
			description:    "Potential risks with external contract interactions",
			recommendation: "Implement checks-effects-interactions pattern, use pull-over-push payment strategy",
		},
	}

	for _, pattern := range externalCallPatterns {
		if strings.Contains(contract, pattern.pattern) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "External Call Risks",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Recommendation: pattern.recommendation,
			})
		}
	}

	return vulnerabilities
}

// calculateSecurityScore computes a security score based on vulnerabilities
func calculateSecurityScore(vulnerabilities []Vulnerability) float64 {
	baseScore := 100.0
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case Critical:
			baseScore -= 25
		case High:
			baseScore -= 15
		case Medium:
			baseScore -= 7
		case Low:
			baseScore -= 3
		}
	}
	return max(0, baseScore)
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

type Vulnerability struct {
	Type           string
	Description    string
	Severity       Severity
	Recommendation string
}

type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
)
