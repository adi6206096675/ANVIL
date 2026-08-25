# engine/decompiler/binary_scanner.py
import os
import re

class NativeBinaryAuditor:
    """Scans compiled C/C++ shared libraries and executables for vulnerabilities."""
    
    def __init__(self):
        # 1. Look for dangerous C function imports
        self.dangerous_functions = [b"strcpy", b"gets", b"sprintf", b"system", b"popen"]
        # 2. Look for hardcoded secrets embedded in binary memory
        self.secret_patterns = {
            "AWS API Key": rb"AKIA[0-9A-Z]{16}",
            "Generic Bearer Token": rb"(?i)bearer [A-Za-z0-9_\-=]{16,}",
            "Private Key": rb"-----BEGIN PRIVATE KEY-----"
        }

    def _extract_strings(self, binary_data: bytes, min_len: int = 4) -> list:
        """Extracts printable ASCII strings from raw binary data (like the Linux 'strings' command)."""
        pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
        return re.findall(pattern, binary_data)

    def scan_binary(self, filepath: str) -> list:
        findings = []
        if not os.path.exists(filepath):
            return findings

        print(f"[ANVIL BINARY SCANNER] Analyzing native library: {os.path.basename(filepath)}")
        try:
            with open(filepath, "rb") as f:
                binary_data = f.read()

                # 1. Scan for hardcoded credentials in binary data
                for secret_type, pattern in self.secret_patterns.items():
                    if re.search(pattern, binary_data):
                        findings.append({
                            "file": filepath,
                            "severity": "CRITICAL",
                            "type": "Embedded Binary Secret",
                            "detail": f"Hardcoded {secret_type} detected in compiled memory."
                        })

                # 2. Extract strings to find dangerous function imports
                binary_strings = self._extract_strings(binary_data)
                found_funcs = [func.decode() for func in self.dangerous_functions if func in binary_strings]
                
                if found_funcs:
                    findings.append({
                        "file": filepath,
                        "severity": "HIGH",
                        "type": "Dangerous C Functions",
                        "detail": f"Binary imports unsafe memory/system functions: {', '.join(found_funcs)}. Risk of buffer overflow or command injection."
                    })

        except Exception as e:
            print(f"[ANVIL ERROR] Failed to parse binary {filepath}: {e}")

        return findings