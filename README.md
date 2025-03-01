# SmartAudit: Solidity Smart Contract Security Analysis Tool 🛡️

## Overview

SmartAudit is an advanced CLI tool designed to perform comprehensive security analysis on Solidity smart contracts. Leveraging AI-enhanced detection and multi-layered vulnerability scanning, SmartAudit helps developers identify and mitigate potential security risks in blockchain applications.

## 🌟 Key Features

- **Comprehensive Vulnerability Detection**
  - Identifies multiple vulnerability types
  - AI-enhanced analysis
  - Detailed security scoring

- **Flexible Analysis Modes**
  - Single contract analysis
  - Batch contract scanning
  - AI-powered deep analysis

- **Customizable Output**
  - Multiple reporting formats (table, JSON, markdown)
  - Severity-based filtering
  - Detailed vulnerability recommendations

## 🚀 Installation

### Prerequisites
- Go 1.18+
- Solidity Compiler

### Install via Go
```
go install github.com/PradyXd/smart-audit/cmd/smartaudit@latest
```
### Install from Source
```
git clone https://github.com/PradyXd/smart-audit.git
cd smart-audit
go mod tidy
go install ./cmd/smartaudit 
```
# Analyze a single smart contract
```
 smartaudit analyze contract.sol
 ```

# Verbose analysis with detailed output
``` 
smartaudit analyze contract.sol -v 
```

# Perform AI-powered deep contract analysis
``` 
smartaudit deep-analyze contract.sol --ai-key YOUR_API_KEY
 ```

# Analyze all contracts in a directory
``` 
smartaudit batch-analyze ./contracts -r
 ```

# Parallel processing for faster analysis
``` 
smartaudit batch-analyze ./contracts -r -p 
```

# Choose output format
``` 
smartaudit analyze contract.sol --output-format json 
```

# Filter vulnerabilities by severity
``` 
smartaudit analyze contract.sol --severity-filter high
 ```

# 🎯 Supported Vulnerability Types
Unsafe Token Transfers
Reentrancy Risks
Timestamp Manipulation
Access Control Weaknesses
Self-Destruct Mechanism Risks
External Call Vulnerabilities
Mathematical Operation Risks

# 🤝 Contributing
Fork the repository
Create your feature branch
Commit your changes
Push to the branch
Create a new Pull Request

# 📄 License
This project is licensed under the Apache 2.0 License - see the LICENSE.md file for details.

# Disclaimer: SmartAudit is a tool to assist in identifying potential vulnerabilities. Always conduct thorough manual code reviews and professional security audits.
