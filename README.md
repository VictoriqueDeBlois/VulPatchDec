# Detecting Vulnerability Patch Commits via Version Filtering and Large Language Models

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)

A novel two-stage framework for automatically detecting vulnerability patch commits in open-source software repositories using version filtering and large language models.

## Overview

This project addresses the critical challenge of automatically identifying vulnerability patches in open-source software repositories. Traditional methods suffer from scalability issues, poor accuracy, and timeliness constraints. Our approach combines version-driven candidate filtering with LLM-based multi-round dialogue voting to achieve accurate and efficient vulnerability patch identification.

## Key Features

- **Two-Stage Detection Framework**: Combines version filtering with LLM-based analysis
- **Version-Driven Filtering**: Reduces search space by extracting affected versions from vulnerability descriptions
- **Multi-Round Dialogue Voting**: Uses GPT-4o-mini with voting mechanisms to handle token limitations and improve stability
- **High Accuracy**: Achieves 77.2% precision and 64.75% recall on real-world datasets
- **Real-Time Capability**: No dependency on external vulnerability advisories or third-party information
- **Multi-Language Support**: Supports C, C++, Java, Golang, Python, and JavaScript

## Architecture

```
CVE Description → Version Extraction → Candidate Filtering → LLM Analysis → Patch Identification
                                    ↓
                     Multi-branch Cross-filtering
                                    ↓
                     Batch Querying + Majority Voting
```

## Performance Comparison

| Method | Precision | Recall | F1 Score | Correctly Predicted CVEs |
|--------|-----------|---------|----------|---------------------------|
| Tracer | 53.03% | 57.34% | 52.35% | 472 (62.9%) |
| **Ours** | **77.20%** | **64.75%** | **65.98%** | **627 (83.6%)** |

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/vulnerability-patch-detector.git
cd vulnerability-patch-detector

# Install dependencies
pip install -r requirements.txt
```

## Configuration

This project requires API keys for GitHub and OpenAI. Set the following environment variables before running:

**Linux / macOS**
```bash
export GITHUB_TOKEN="your_github_personal_access_token"
export OPENAI_API_KEY="your_openai_api_key"
```

**Windows (Command Prompt)**
```cmd
set GITHUB_TOKEN=your_github_personal_access_token
set OPENAI_API_KEY=your_openai_api_key
```

**Windows (PowerShell)**
```powershell
$env:GITHUB_TOKEN="your_github_personal_access_token"
$env:OPENAI_API_KEY="your_openai_api_key"
```

> You can also create a `.env` file in the project root and load it with [python-dotenv](https://github.com/theskumar/python-dotenv).

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub Personal Access Token for accessing the GitHub API |
| `OPENAI_API_KEY` | OpenAI API key for GPT-4o-mini access |

## Dependencies

- Python 3.10+
- OpenAI GPT-4o-mini API access
- ANTLR4 for code parsing
- Required Python packages (see `requirements.txt`)

## Dataset

The project uses a comprehensive dataset containing:
- **750 test vulnerabilities** from 2020-2024
- **61,780 candidate commits**
- **Multiple programming languages**
- **Real-world open-source projects**

Dataset statistics:
- Training: 1,027 vulnerabilities
- Validation: 265 vulnerabilities  
- Test: 750 vulnerabilities
- Total commits: 98,934

## License

This project is licensed under the MIT License

## Contact

For questions or collaboration opportunities, please open an issue or contact the development team.
