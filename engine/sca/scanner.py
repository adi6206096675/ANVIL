# engine/sca/scanner.py
import os
import json
import urllib.request
import urllib.error

class AnvilSCAScanner:
    """Audits open-source project dependencies against known vulnerability databases (OSV API)."""

    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"

    def scan_manifest(self, manifest_path: str) -> list:
        findings = []
        if not os.path.exists(manifest_path):
            return findings

        filename = os.path.basename(manifest_path).lower()
        print(f"[ANVIL SCA] Auditing dependency manifest: {filename}")

        if filename == "requirements.txt":
            dependencies = self._parse_requirements_txt(manifest_path)
            ecosystem = "PyPI"
        elif filename == "package.json":
            dependencies = self._parse_package_json(manifest_path)
            ecosystem = "npm"
        else:
            print(f"[ANVIL SCA] Unsupported manifest type: {filename}")
            return findings

        for name, version in dependencies.items():
            cves = self._query_osv_api(ecosystem, name, version)
            for cve in cves:
                findings.append({
                    "manifest": manifest_path,
                    "package": name,
                    "version": version,
                    "severity": cve.get("severity", "HIGH"),
                    "cve_id": cve.get("id", "UNKNOWN_CVE"),
                    "detail": cve.get("details", "Known vulnerability detected in dependency.")[:150] + "..."
                })

        return findings

    def _parse_requirements_txt(self, filepath: str) -> dict:
        deps = {}
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "==" in line:
                    parts = line.split("==")
                    deps[parts[0].strip()] = parts[1].strip()
        return deps

    def _parse_package_json(self, filepath: str) -> dict:
        deps = {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, ver in raw_deps.items():
                    clean_ver = ver.replace("^", "").replace("~", "").strip()
                    deps[name] = clean_ver
        except Exception:
            pass
        return deps

    def _query_osv_api(self, ecosystem: str, package_name: str, version: str) -> list:
        payload = json.dumps({
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version
        }).encode("utf-8")

        req = urllib.request.Request(
            self.osv_api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=3.0) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("vulns", [])
        except (urllib.error.URLError, TimeoutError):
            return []


if __name__ == "__main__":
    scanner = AnvilSCAScanner()
    # Test against a local requirements file
    results = scanner.scan_manifest("requirements.txt")
    for r in results:
        print(f" -> [{r['severity']}] {r['package']} ({r['version']}): {r['cve_id']} - {r['detail']}")