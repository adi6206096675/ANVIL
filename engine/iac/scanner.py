# engine/iac/scanner.py
import os
import re

class AnvilIaCScanner:
    """Audits Infrastructure-as-Code (IaC) files for deployment misconfigurations."""

    def __init__(self):
        self.dockerfile_rules = [
            {
                "id": "IAC-DOCKER-01",
                "severity": "HIGH",
                "pattern": r"^USER\s+root",
                "message": "Container explicitly configured to run as root user."
            },
            {
                "id": "IAC-DOCKER-02",
                "severity": "MEDIUM",
                "pattern": r"^FROM\s+.*:latest",
                "message": "Base image uses unpinned ':latest' tag, causing non-deterministic builds."
            },
            {
                "id": "IAC-DOCKER-03",
                "severity": "CRITICAL",
                "pattern": r"(?i)(ENV|ARG)\s+.*(password|secret|key|token)\s*=",
                "message": "Hardcoded credential or secret detected in build environment instructions."
            }
        ]

    def scan_file(self, filepath: str) -> list:
        findings = []
        if not os.path.exists(filepath):
            return findings

        filename = os.path.basename(filepath).lower()
        print(f"[ANVIL IaC] Scanning infrastructure manifest: {filename}")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if "dockerfile" in filename:
            has_user_instruction = False
            for line_no, line in enumerate(lines, 1):
                clean_line = line.strip()
                if clean_line.startswith("USER "):
                    has_user_instruction = True

                for rule in self.dockerfile_rules:
                    if re.search(rule["pattern"], clean_line, re.MULTILINE):
                        findings.append({
                            "file": filepath,
                            "line": line_no,
                            "rule_id": rule["id"],
                            "severity": rule["severity"],
                            "detail": rule["message"]
                        })

            if not has_user_instruction:
                findings.append({
                    "file": filepath,
                    "line": 1,
                    "rule_id": "IAC-DOCKER-04",
                    "severity": "HIGH",
                    "detail": "Dockerfile missing explicit 'USER' instruction. Defaults to root execution."
                })

        return findings


if __name__ == "__main__":
    scanner = AnvilIaCScanner()
    results = scanner.scan_file("Dockerfile")
    for r in results:
        print(f" -> [{r['severity']}] Line {r['line']}: {r['detail']}")