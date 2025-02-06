#!/usr/bin/env python3
import os
import sys
import git
import shutil
from pathlib import Path
import openai
from dotenv import load_dotenv
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import json

print("[+] START: GitHub Repository Analyzer")
print("[~] Importing required modules...")

# Pydantic models for structured output
class CodePattern(BaseModel):
    pattern_type: str = Field(..., description="Type of pattern found (environment, error, logging, structure)")
    found_patterns: List[str] = Field(..., description="List of specific patterns found in the code")
    line_numbers: List[int] = Field(..., description="Line numbers where patterns were found")

class RunnerCompatibleCode(BaseModel):
    original_file: str = Field(..., description="Name of the original file")
    runner_compatible_version: str = Field(..., description="Complete runner-compatible version of the code")
    changes_made: List[str] = Field(..., description="List of changes made to make the code runner-compatible")

class FileAnalysis(BaseModel):
    file_name: str = Field(..., description="Name of the analyzed file")
    patterns_found: List[CodePattern] = Field(..., description="Patterns found in the file")
    issues: List[str] = Field(..., description="Issues identified in the code")
    recommendations: List[str] = Field(..., description="Specific recommendations for improvement")
    runner_compatible: Optional[RunnerCompatibleCode] = Field(None, description="Runner-compatible version of the code if needed")

class RepositoryAnalysis(BaseModel):
    overall_score: str = Field(..., description="Overall repository score (Excellent: 90-100, Good: 70-89, Fair: 50-69, Poor: 0-49)")
    critical_issues: List[str] = Field(..., description="Critical issues that need immediate attention")
    recommendations: List[str] = Field(..., description="Prioritized list of recommendations")
    ecosystem_compatibility: List[str] = Field(..., description="List of compatibility issues with runner ecosystem")

class GitHubRepoAnalyzer:
    def __init__(self, repo_url: str):
        print("[~] Initializing analyzer...")
        
        # Load environment variables
        print("[~] Loading environment variables...")
        load_dotenv()
        print("[+] Environment variables loaded")
        
        # Initialize OpenAI client
        print("[~] Setting up OpenAI client...")
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            print("[ERROR] OPENAI_API_KEY environment variable is not set")
            raise ValueError("OPENAI_API_KEY environment variable is not set")
        
        self.openai_client = openai.OpenAI(api_key=self.api_key)
        print("[+] OpenAI client initialized")
        
        self.repo_url = repo_url
        self.repo_name = repo_url.split('/')[-1].replace('.git', '')
        
        # Set up workspace directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.workspace_dir = os.path.join(script_dir, self.repo_name)
        os.makedirs(self.workspace_dir, exist_ok=True)
        print(f"[+] Workspace directory created: {self.workspace_dir}")
        
        print(f"[+] Repository name identified: {self.repo_name}")
        
        # Template patterns we're looking for
        self.template_patterns = {
            'environment_handling': [
                'load_dotenv()',
                'os.environ',
                'os.getenv',
                'environment variable validation'
            ],
            'error_handling': [
                'try/except blocks',
                'sys.exit(1)',
                'error messages to stderr'
            ],
            'logging_patterns': [
                'print statements with prefixes',
                'stdout/stderr separation',
                'debug logging'
            ],
            'file_structure': [
                'main() function',
                '__name__ == "__main__"',
                'type hints',
                'docstrings'
            ]
        }
        print("[+] Template patterns loaded")

    def _analyze_code_structure(self, file_content: str, file_name: str) -> FileAnalysis:
        """Analyze code structure using OpenAI with structured output."""
        print(f"[~] Analyzing code structure for {file_name}...")
        try:
            response = self.openai_client.beta.chat.completions.parse(
                model="o3-mini-2025-01-31",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a code analysis expert. Your task is to analyze code following runner ecosystem best practices and generate runner-compatible versions. "
                            "In addition, your runner-compatible output must include logic to produce a final output file—similar to the Shodan IP Lookup example—where a report (or results) is written to a file and its path is printed to stdout.\n\n"
                            "Here are examples of good patterns to look for and implement:\n\n"
                            "1. Proper Logging and Progress Tracking:\n"
                            "```python\n"
                            "print(\"[+] START: Process Name\")\n"
                            "print(\"[~] Importing required modules...\")\n"
                            "print(\"[+] Module imported successfully\")\n"
                            "print(\"[ERROR] Something went wrong: {error}\")\n"
                            "print(\"[DEBUG] Variable value: {value}\")\n"
                            "```\n\n"
                            "2. Environment Setup:\n"
                            "```python\n"
                            "print(\"[~] Setting up HOME cache directory...\")\n"
                            "root_dir = '/tmp/root'\n"
                            "os.makedirs(root_dir, exist_ok=True)\n"
                            "os.chmod(root_dir, 0o777)\n"
                            "os.environ[\"HOME\"] = root_dir\n"
                            "print(f\"[+] HOME set to: {os.environ['HOME']}\")\n"
                            "```\n\n"
                            "3. Error Handling:\n"
                            "```python\n"
                            "try:\n"
                            "    print(\"[~] Processing task...\")\n"
                            "    # task code here\n"
                            "except Exception as e:\n"
                            "    print(f\"[ERROR] An unexpected error occurred: {str(e)}\")\n"
                            "    sys.exit(1)\n"
                            "```\n\n"
                            "4. Command Line Arguments:\n"
                            "```python\n"
                            "print(\"[~] Checking command line arguments...\")\n"
                            "if len(sys.argv) < 2:\n"
                            "    print(\"[ERROR] Please provide required arguments\")\n"
                            "    sys.exit(1)\n"
                            "```\n\n"
                            "5. File Operations and Output File Creation (as in the Shodan example):\n"
                            "```python\n"
                            "import os\n"
                            "os.makedirs(\"outputs\", exist_ok=True)\n"
                            "output_file = os.path.join(\"outputs\", \"results.txt\")\n"
                            "with open(output_file, 'w', encoding='utf-8') as f:\n"
                            "    f.write(\"Your report content here\")\n"
                            "print(f\"[+] Results saved to: {output_file}\")\n"
                            "```\n\n"
                            "Example of a Complete Runner-Compatible Script:\n"
                            "```python\n"
                            "print(\"[+] START: DNS Analysis Tool\")\n"
                            "print(\"[~] Importing required modules...\")\n\n"
                            "import os\n"
                            "import sys\n"
                            "from datetime import datetime\n"
                            "print(\"[+] Base modules imported successfully\")\n\n"
                            "try:\n"
                            "    import dns.resolver\n"
                            "    import dns.reversename\n"
                            "    print(\"[+] DNS modules imported successfully\")\n"
                            "except ImportError as e:\n"
                            "    print(f\"[ERROR] Failed to import DNS modules: {str(e)}\")\n"
                            "    sys.exit(1)\n\n"
                            "def process_domain(domain: str) -> dict:\n"
                            "    print(f\"[~] Processing domain: {domain}\")\n"
                            "    try:\n"
                            "        result = dns.resolver.resolve(domain, 'A')\n"
                            "        print(\"[+] DNS resolution successful\")\n"
                            "        return {\"records\": [str(r) for r in result]}\n"
                            "    except Exception as e:\n"
                            "        print(f\"[ERROR] DNS resolution failed: {str(e)}\")\n"
                            "        return {\"error\": str(e)}\n\n"
                            "def main():\n"
                            "    print(\"[~] Checking command line arguments...\")\n"
                            "    if len(sys.argv) != 2:\n"
                            "        print(\"[ERROR] Please provide a domain name\")\n"
                            "        print(\"Usage: python script.py <domain>\")\n"
                            "        sys.exit(1)\n\n"
                            "    domain = sys.argv[1]\n"
                            "    print(f\"[DEBUG] Domain to analyze: {domain}\")\n\n"
                            "    result = process_domain(domain)\n"
                            "    if \"error\" in result:\n"
                            "        print(f\"[ERROR] Analysis failed: {result['error']}\")\n"
                            "        sys.exit(1)\n\n"
                            "    # Create an output folder, write the report to a file, and print its path\n"
                            "    os.makedirs(\"outputs\", exist_ok=True)\n"
                            "    output_file = os.path.join(\"outputs\", f\"{domain}_dns_report.txt\")\n"
                            "    with open(output_file, 'w', encoding='utf-8') as f:\n"
                            "        f.write(str(result))\n"
                            "    print(f\"[+] Report written to: {output_file}\")\n\n"
                            "if __name__ == \"__main__\":\n"
                            "    main()\n\n"
                            "print(\"[+] END: DNS Analysis Tool\")\n"
                            "```\n\n"
                            "Important: If the file requires modifications to meet runner compatibility standards, output a complete, rewritten version in the runner_compatible field. The content of the runner_compatible field must be a full file content that can be directly saved and executed, including logic to generate an output file."
                        )
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this code:\n\n{file_content}"
                    }
                ],
                response_format=FileAnalysis
            )
            print(f"[+] Analysis completed for {file_name}")
            return response.choices[0].message.parsed
        except Exception as e:
            print(f"[ERROR] Analysis failed for {file_name}: {str(e)}")
            return FileAnalysis(
                file_name=file_name,
                patterns_found=[],
                issues=[f"Error during analysis: {str(e)}"],
                recommendations=["Unable to complete analysis"]
            )

    def _find_python_files(self) -> List[Path]:
        """Find all Python files in the repository."""
        print("[~] Searching for Python files...")
        python_files = []
        for path in Path(self.workspace_dir).rglob('*.py'):
            if 'venv' not in str(path) and 'test' not in str(path):
                python_files.append(path)
        print(f"[+] Found {len(python_files)} Python files")
        return python_files

    def _generate_repository_analysis(self, file_analyses: List[FileAnalysis]) -> RepositoryAnalysis:
        """Generate final repository analysis using OpenAI."""
        print("[~] Generating repository-level analysis...")
        try:
            response = self.openai_client.beta.chat.completions.parse(
                model="o3-mini-2025-01-31",
                messages=[
                    {"role": "system", "content": """Generate a comprehensive repository analysis based on the file analyses provided.

Example of Good Runner Code Structure:
```python
print("[+] START: Process Name")

# Module imports with logging
print("[~] Importing required modules...")
import os
print("[+] os module imported")
import sys
print("[+] sys module imported")

# Environment setup
print("[~] Setting up environment...")
root_dir = '/tmp/root'
os.makedirs(root_dir, exist_ok=True)
os.environ["HOME"] = root_dir

# Main process in try-except
try:
    print("[~] Starting main process...")
    # Main logic here
    print("[+] Process completed successfully")
except Exception as e:
    print(f"[ERROR] Process failed: {str(e)}")
    sys.exit(1)

# Create an output file with results
os.makedirs("outputs", exist_ok=True)
output_file = os.path.join("outputs", "results.txt")
with open(output_file, 'w', encoding='utf-8') as f:
    f.write("Report details here")
print(f"[+] Results saved to: {output_file}")

print("[+] END: Process Name")
```

Focus on:
1. Overall code quality and consistency with the above pattern
2. Critical issues that need immediate attention
3. Ecosystem compatibility concerns
4. Actionable recommendations for improvement

The overall_score should be one of these text values:
- "Excellent (90-100): Follows all runner patterns"
- "Good (70-89): Minor improvements needed"
- "Fair (50-69): Missing several key patterns"
- "Poor (0-49): Major refactoring required"
"""},
                    {"role": "user", "content": f"Generate repository analysis based on these file analyses:\n\n{[analysis.model_dump() for analysis in file_analyses]}"}
                ],
                response_format=RepositoryAnalysis
            )
            print("[+] Repository analysis completed")
            return response.choices[0].message.parsed
        except Exception as e:
            print(f"[ERROR] Repository analysis failed: {str(e)}")
            return RepositoryAnalysis(
                overall_score="Poor (0-49): Analysis failed",
                critical_issues=[f"Error generating repository analysis: {str(e)}"],
                recommendations=["Unable to complete repository analysis"],
                ecosystem_compatibility=[]
            )

    def analyze(self) -> str:
        """Main method to analyze the repository."""
        print(f"[~] Starting analysis for repository: {self.repo_url}")
        try:
            # Clone repository into workspace directory
            print(f"[~] Cloning repository {self.repo_url}...")
            try:
                git.Repo.clone_from(self.repo_url, self.workspace_dir)
                print("[+] Repository cloned successfully")
            except git.exc.GitCommandError as e:
                print(f"[ERROR] Failed to clone repository: {str(e)}")
                raise
            
            # Find and analyze Python files
            python_files = self._find_python_files()
            file_analyses = []
            
            for file_path in python_files:
                print(f"[~] Processing {file_path.name}...")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        analysis = self._analyze_code_structure(content, file_path.name)
                        file_analyses.append(analysis)
                        
                        # Check if a runner-compatible version was generated.
                        if analysis.runner_compatible and analysis.runner_compatible.runner_compatible_version:
                            runner_file = os.path.join(
                                self.workspace_dir, 
                                'runner_compatible_' + analysis.runner_compatible.original_file
                            )
                            print(f"[~] Creating runner-compatible version: {runner_file}")
                            with open(runner_file, 'w', encoding='utf-8') as rf:
                                rf.write(analysis.runner_compatible.runner_compatible_version)
                            print(f"[+] Runner-compatible version created: {runner_file}")
                        else:
                            # Fallback: if no runner_compatible output, save the original file with a warning
                            runner_file = os.path.join(
                                self.workspace_dir,
                                'runner_compatible_' + file_path.name
                            )
                            print(f"[WARNING] No runner-compatible version produced for {file_path.name}. Saving original file as fallback: {runner_file}")
                            with open(runner_file, 'w', encoding='utf-8') as rf:
                                rf.write(content)
                except Exception as e:
                    print(f"[ERROR] Failed to process {file_path.name}: {str(e)}")
                    continue
            
            # Generate comprehensive repository analysis
            repo_analysis = self._generate_repository_analysis(file_analyses)
            
            # Create structured output
            print("[~] Preparing final output...")
            output = {
                "repository_name": self.repo_name,
                "file_analyses": [analysis.model_dump() for analysis in file_analyses],
                "repository_analysis": repo_analysis.model_dump()
            }
            
            # Save output to file in workspace directory
            output_file = os.path.join(self.workspace_dir, f"{self.repo_name}_analysis.json")
            print(f"[~] Saving analysis to {output_file}...")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)
            
            print(f"[+] Analysis complete! Results saved to: {output_file}")
            return output_file
            
        except Exception as e:
            print(f"[ERROR] Analysis failed: {str(e)}")
            raise

def main():
    print("[~] Checking command line arguments...")
    if len(sys.argv) != 2:
        print("[ERROR] Invalid number of arguments")
        print("Usage: python github_repo_analyzer.py <github_repo_url>")
        sys.exit(1)
    
    try:
        repo_url = sys.argv[1]
        print(f"[DEBUG] Repository URL: {repo_url}")
        
        analyzer = GitHubRepoAnalyzer(repo_url)
        output_file = analyzer.analyze()
        print(f"[+] Analysis saved to: {output_file}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
print("[+] END: GitHub Repository Analyzer") 