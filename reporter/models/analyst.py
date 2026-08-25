# reporter/models/analyst.py
import os
import re

class AnvilWebReporter:
    def __init__(self):
        print("[ANVIL CORE] Initializing Deterministic Local Analyst with Auto-Patcher...")

    def parse_log_file(self, log_file_path: str) -> dict:
        """Extracts structured metadata from raw crash log files."""
        metadata = {
            "payload": "",
            "exit_code": "",
            "raw_logs": "",
            "coverage": []
        }
        
        if not os.path.exists(log_file_path):
            return metadata

        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if line_str.startswith("PAYLOAD:"):
                    metadata["payload"] = line_str.replace("PAYLOAD:", "").strip().strip("'\"")
                elif line_str.startswith("EXIT:"):
                    metadata["exit_code"] = line_str.replace("EXIT:", "").strip()
                elif line_str.startswith("LOGS:"):
                    metadata["raw_logs"] = line_str.replace("LOGS:", "").strip()
                elif "ANVIL_COVERAGE:" in line_str:
                    cov_match = re.search(r"ANVIL_COVERAGE:(\[.*?\])", line_str)
                    if cov_match:
                        try:
                            metadata["coverage"] = eval(cov_match.group(1))
                        except Exception:
                            pass
                else:
                    metadata["raw_logs"] += f"\n{line_str}"

        return metadata

    def generate_patch(self, vulnerability: str) -> str:
        """Generates deterministic remediation code based on the exact vulnerability."""
        patch = "\n--- RECOMMENDED CODE PATCH ---\n"
        
        if "Buffer Overflow" in vulnerability:
            patch += "```python\n"
            patch += "# Enforce strict length boundaries BEFORE processing\n"
            patch += "MAX_LENGTH = 256\n"
            patch += "if len(user_input) > MAX_LENGTH:\n"
            patch += "    raise ValueError('Input exceeds memory safety envelope.')\n"
            patch += "process_buffer(user_input)\n"
            patch += "```"
        
        elif "SQL Injection" in vulnerability:
            patch += "```python\n"
            patch += "# Use Parameterized Queries (sqlite3 example)\n"
            patch += "cursor.execute('SELECT * FROM users WHERE username = ?', (user_input,))\n"
            patch += "```"
            
        elif "Command Injection" in vulnerability:
            patch += "```python\n"
            patch += "import subprocess\n"
            patch += "# Pass arguments as a list, NEVER as a single concatenated string\n"
            patch += "subprocess.run(['ping', '-c', '4', user_input], check=True)\n"
            patch += "```"
            
        elif "Cross-Site Scripting" in vulnerability:
            patch += "```python\n"
            patch += "import html\n"
            patch += "# Sanitize input before rendering\n"
            patch += "safe_output = html.escape(user_input)\n"
            patch += "return f'<div>{safe_output}</div>'\n"
            patch += "```"
            
        elif "Path Traversal" in vulnerability:
            patch += "```python\n"
            patch += "import os\n"
            patch += "safe_dir = '/var/www/html/'\n"
            patch += "target_path = os.path.abspath(os.path.join(safe_dir, user_input))\n"
            patch += "if not target_path.startswith(safe_dir):\n"
            patch += "    raise PermissionError('Path Traversal Attempt Blocked')\n"
            patch += "```"

        elif "Integer Overflow" in vulnerability:
            patch += "```python\n"
            patch += "# Validate 32-bit integer boundaries\n"
            patch += "MIN_INT32, MAX_INT32 = -2147483648, 2147483647\n"
            patch += "val = int(user_input)\n"
            patch += "if not (MIN_INT32 <= val <= MAX_INT32):\n"
            patch += "    raise ValueError('Integer Overflow Detected: Input outside 32-bit range.')\n"
            patch += "```"

        elif "Poison Null Byte" in vulnerability:
            patch += "```python\n"
            patch += "# Strip null characters before processing\n"
            patch += "safe_input = user_input.replace('\\x00', '').replace('\\\\x00', '')\n"
            patch += "```"
            
        else:
            patch += "Manual logic review required. See remediation notes above."
            
        return patch

    def generate_report(self, log_file_path: str) -> str:
        """Determines vulnerability type based on strict rules and signature checks."""
        data = self.parse_log_file(log_file_path)
        exit_code = data["exit_code"]
        raw_logs = data["raw_logs"].lower()
        payload = data["payload"]
        cov_count = len(data["coverage"])

        report = ["ANVIL AUTOMATED CORE REVIEW", "-" * 30]

        # --- RULE 1: POISON NULL BYTE ---
        if "embedded null character" in raw_logs or "\x00" in payload or "\\x00" in payload:
            report.append("STATUS: CRITICAL INFRASTRUCTURE BREACH DETECTED")
            report.append("VULNERABILITY: Poison Null Byte Injection")
            report.append("ANALYSIS: System API encountered an unhandled null character terminator in parameter input.")
            report.append("REMEDIATION: Implement sanitization filter to strip null bytes ('\\x00') before string handling.")

        # --- RULE 2: MEMORY CORRUPTION / SEGFAULT ---
        elif exit_code in ["139", "134"] or "segmentation fault" in raw_logs or "memory corruption" in raw_logs:
            report.append("STATUS: CRITICAL MEMORY CORRUPTION DETECTED")
            report.append("VULNERABILITY: Segmentation Fault / Buffer Overflow")
            report.append(f"ANALYSIS: Target process shattered with Exit Signal {exit_code}. Input payload (Length: {len(payload)}) breached memory bounds.")
            report.append("REMEDIATION: Enforce strict length boundary checks and use memory-safe buffer structures.")

        # --- RULE 3: RESOURCE EXHAUSTION (MEMORY LEAK) ---
        elif exit_code == "OOM_KILL" or "memory limit exceeded" in raw_logs or "oom" in raw_logs:
            mem_match = re.search(r"(\d+\.\d+|\d+)\s*mb", raw_logs)
            mem_info = f" ({mem_match.group(0)})" if mem_match else ""
            report.append("STATUS: RESOURCE EXHAUSTION DETECTED")
            report.append("VULNERABILITY: Unbounded Memory Allocation / Memory Leak")
            report.append(f"ANALYSIS: Target exceeded memory safety envelope{mem_info}. Process terminated by Chokehold monitor.")
            report.append("REMEDIATION: Introduce strict limits on allocation containers and verify object deallocation.")

        # --- RULE 4: RESOURCE EXHAUSTION (TIMEOUT / DOS) ---
        elif exit_code == "TIMEOUT" or "process completely hung" in raw_logs:
            report.append("STATUS: RESOURCE EXHAUSTION DETECTED")
            report.append("VULNERABILITY: Infinite Loop / Execution Timeout (DoS)")
            report.append("ANALYSIS: Target execution hung without yielding state back to the runtime worker within threshold limits.")
            report.append("REMEDIATION: Implement rigid execution time limits and inspect loop termination parameters.")

        # --- RULE 5: SQL INJECTION / LOGIC BREACH ---
        elif exit_code == "140" or "select" in raw_logs or "executed query" in raw_logs or "authentication bypassed" in raw_logs:
            report.append("STATUS: CRITICAL LOGIC BREACH DETECTED")
            report.append("VULNERABILITY: SQL Injection (SQLi) / Authentication Bypass")
            report.append("ANALYSIS: Payload altered execution query structure, forcing truthy evaluation in database backend.")
            report.append("REMEDIATION: Replace dynamic string concatenation with Prepared Statements (Parameterized Queries).")

        # --- RULE 6: OS COMMAND INJECTION ---
        elif exit_code == "140" or "command execution detected" in raw_logs or "subprocess created" in raw_logs:
            report.append("STATUS: CRITICAL LOGIC BREACH DETECTED")
            report.append("VULNERABILITY: OS Command Injection")
            report.append("ANALYSIS: Application passed unsanitized input to system shell execution layer.")
            report.append("REMEDIATION: Avoid system shell invocation. Implement strict argument whitelisting.")

        # --- RULE 7: PATH TRAVERSAL ---
        elif exit_code == "141" or "sensitive file" in raw_logs or "file system node" in raw_logs:
            report.append("STATUS: CRITICAL LOGIC BREACH DETECTED")
            report.append("VULNERABILITY: Directory Traversal / Path Traversal")
            report.append("ANALYSIS: Directory breakout payload granted unauthorized reading outside designated working directories.")
            report.append("REMEDIATION: Resolve relative paths against standard root directories and restrict traversal sequences ('..').")

        # --- RULE 8: CROSS-SITE SCRIPTING (XSS) ---
        elif exit_code == "142" or "rendered output trace" in raw_logs or "<script>" in payload:
            report.append("STATUS: UI LOGIC BREACH DETECTED")
            report.append("VULNERABILITY: Cross-Site Scripting (XSS)")
            report.append("ANALYSIS: User-controlled input reflected directly into output context without entity encoding.")
            report.append("REMEDIATION: Apply context-aware HTML entity encoding prior to rendering string structures.")

        # --- RULE 9: INTEGER OVERFLOW ---
        elif exit_code == "143" or "arithmeticerror" in raw_logs or "integer overflow" in raw_logs:
            report.append("STATUS: CRITICAL MATH FAULT DETECTED")
            report.append("VULNERABILITY: Integer Overflow / Underflow")
            report.append("ANALYSIS: Arithmetic evaluation pushed values past fixed primitive bit bounds.")
            report.append("REMEDIATION: Validate input dynamic ranges before executing arithmetic operations.")

        # --- FALLBACK RULE ---
        else:
            report.append("STATUS: UNKNOWN STRUCTURAL FAILURE")
            report.append(f"EXIT SIGNAL: {exit_code or 'UNKNOWN'}")
            report.append(f"LINES MAPPED: {cov_count}")
            report.append(f"RAW TRACE: {data['raw_logs'][:150]}...")

        # Find the detected vulnerability and attach the patch code
        vuln_type = next((line for line in report if "VULNERABILITY:" in line), "")
        if vuln_type:
            report.append(self.generate_patch(vuln_type))

        return "\n".join(report)


if __name__ == "__main__":
    reporter = AnvilWebReporter()
    verdict = reporter.generate_report("../../tests/samples/crash_report.log")
    print(verdict)