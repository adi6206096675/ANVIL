# engine/sast/scanner.py
import os
import re
import ast
import shutil
import zipfile
import subprocess

class AnvilASTVisitor(ast.NodeVisitor):
    """Parses Python Abstract Syntax Trees to identify dangerous code patterns."""
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def visit_Call(self, node):
        # 1. Detect dangerous dynamic code evaluation
        if isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec"]:
                self.findings.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "severity": "CRITICAL",
                    "type": "Dynamic Code Execution",
                    "detail": f"Use of '{node.func.id}()' enables arbitrary code execution."
                })

            # 2. Detect insecure deserialization
            elif node.func.id in ["pickle.loads", "loads"]:
                self.findings.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "severity": "HIGH",
                    "type": "Insecure Deserialization",
                    "detail": "Unsafe object deserialization detected (pickle)."
                })

        # 3. Detect dangerous OS command execution
        elif isinstance(node.func, ast.Attribute):
            # os.system(...)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                self.findings.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "severity": "HIGH",
                    "type": "OS Command Injection Risk",
                    "detail": "Use of 'os.system()' passed to command shell."
                })
            
            # subprocess.Popen(..., shell=True)
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.findings.append({
                            "file": self.filepath,
                            "line": node.lineno,
                            "severity": "HIGH",
                            "type": "Subprocess Shell Execution",
                            "detail": "subprocess call initiated with 'shell=True'."
                        })

        self.generic_visit(node)


class AnvilStaticScanner:
    def __init__(self):
        print("[ANVIL SAST] Initializing Static Code Audit Engine...")
        self.secret_patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key / Token": r"(?i)(api[_-]?key|secret|password|bearer|token)\s*=\s*['\"][A-Za-z0-9_\-=]{16,}['\"]",
            "Private Key Header": r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",
            "Hardcoded JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }

    def unpack_target(self, target_path: str, extract_dir: str) -> str:
        """Handles target preparation: extracts ZIP/APK or resolves standard directories."""
        if os.path.isdir(target_path):
            return target_path

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path '{target_path}' does not exist.")

        os.makedirs(extract_dir, exist_ok=True)

        # Handle Android APK decompilation
        if target_path.endswith(".apk"):
            jadx_bin = shutil.which("jadx")
            if jadx_bin:
                print(f"[ANVIL SAST] Decompiling APK via JADX: {target_path}")
                subprocess.run([jadx_bin, "-d", extract_dir, target_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return extract_dir
            else:
                print("[ANVIL SAST] JADX CLI not detected on system PATH. Extracting raw APK archive...")
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                return extract_dir

        # Handle standard ZIP archives
        elif target_path.endswith(".zip"):
            print(f"[ANVIL SAST] Unpacking archive: {target_path}")
            with zipfile.ZipFile(target_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            return extract_dir

        return target_path

    def scan_file_content(self, filepath: str) -> list:
        """Runs regex audit for hardcoded secrets and credentials."""
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
                for secret_type, pattern in self.secret_patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Estimate line number
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            "file": filepath,
                            "line": line_num,
                            "severity": "CRITICAL",
                            "type": "Hardcoded Secret",
                            "detail": f"Matched pattern for '{secret_type}'"
                        })

                # AST Parsing for Python source files
                if filepath.endswith(".py"):
                    try:
                        tree = ast.parse(content, filename=filepath)
                        visitor = AnvilASTVisitor(filepath)
                        visitor.visit(tree)
                        findings.extend(visitor.findings)
                    except SyntaxError:
                        pass # Ignore broken syntax in malformed files
                        
        except Exception as e:
            pass

        return findings

    def run_sast(self, target_path: str) -> list:
        """Main execution sequence for static code analysis."""
        workspace = "tests/samples/sast_extracted"
        target_dir = self.unpack_target(target_path, workspace)
        all_findings = []

        print(f"[ANVIL SAST] Commencing static scan on unpacked target: {target_dir}")

        if os.path.isfile(target_dir):
            all_findings.extend(self.scan_file_content(target_dir))
        else:
            for root, _, files in os.walk(target_dir):
                for file in files:
                    # Target source files, configs, and manifests
                    if file.endswith((".py", ".java", ".js", ".json", ".xml", ".properties", ".env", ".yaml")):
                        full_path = os.path.join(root, file)
                        findings = self.scan_file_content(full_path)
                        all_findings.extend(findings)

        # Cleanup extracted temporary workspace
        if os.path.exists(workspace) and workspace != target_path:
            shutil.rmtree(workspace, ignore_errors=True)

        return all_findings

if __name__ == "__main__":
    scanner = AnvilStaticScanner()
    results = scanner.run_sast("tests/samples/vuln.py")
    print(f"\n[ANVIL SAST] Audit complete. Total findings: {len(results)}")
    for f in results:
        print(f" -> [{f['severity']}] {f['type']} at line {f['line']}: {f['detail']}")