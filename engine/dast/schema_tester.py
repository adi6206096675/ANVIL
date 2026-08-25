# engine/dast/schema_tester.py
import json
import urllib.request
import urllib.error
import os

from engine.rules.parser import AnvilRuleEngine

class APISchemaTester:
    """
    Defensive API test runner that validates endpoint resilience 
    and actively deploys YAML-defined attack rules against web targets.
    """
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        # Initialize Rule Engine
        rule_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../rules"))
        self.rule_engine = AnvilRuleEngine(rule_dir)

    def test_endpoint_resilience(self, endpoint: str, test_cases: list) -> list:
        """
        Submits structured test boundaries to verify that the target API 
        handles invalid requests with appropriate 4xx client error status codes.
        """
        results = []
        target_url = f"{self.base_url}{endpoint}"

        for case in test_cases:
            payload_data = json.dumps(case["payload"]).encode("utf-8")
            req = urllib.request.Request(
                target_url,
                data=payload_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    status = response.status
                    
                    # If an invalid payload returns 200 OK, the API lacks proper input validation
                    status_pass = (status in case["expected_status"])
                    results.append({
                        "case_name": case["name"],
                        "status_code": status,
                        "passed": status_pass,
                        "notes": "API accepted request" if status == 200 else "Handled normally"
                    })

            except urllib.error.HTTPError as e:
                # 4xx error codes demonstrate proper API boundary validation
                status_pass = (e.code in case["expected_status"])
                results.append({
                    "case_name": case["name"],
                    "status_code": e.code,
                    "passed": status_pass,
                    "notes": f"Server rejected input with HTTP {e.code}"
                })

            except urllib.error.URLError as e:
                results.append({
                    "case_name": case["name"],
                    "status_code": "CONN_REFUSED",
                    "passed": False,
                    "notes": f"Target endpoint unreachable: {e.reason}"
                })

        return results

    def execute_yaml_attacks(self, endpoint: str) -> list:
        """
        Iterates over all YAML rules, fires their payloads as JSON input, 
        and validates the HTTP response using YAML matchers.
        """
        results = []
        target_url = f"{self.base_url}{endpoint}"
        
        if not self.rule_engine.loaded_rules:
            print("[ANVIL DAST] No YAML rules found to execute.")
            return results

        print(f"[ANVIL DAST] Executing targeted YAML attack rules against {target_url}...")

        for rule in self.rule_engine.loaded_rules:
            rule_id = rule["id"]
            severity = rule.get("info", {}).get("severity", "UNKNOWN")
            payloads = rule.get("attack", {}).get("payloads", [])
            
            for payload in payloads:
                # Inject payload into a standard JSON field for testing
                attack_data = json.dumps({"username": payload, "email": "test@example.com"}).encode("utf-8")
                req = urllib.request.Request(
                    target_url, 
                    data=attack_data, 
                    headers={"Content-Type": "application/json"}, 
                    method="POST"
                )
                
                status_code = 0
                response_body = ""
                
                try:
                    with urllib.request.urlopen(req, timeout=3.0) as response:
                        status_code = response.status
                        response_body = response.read().decode('utf-8', errors='ignore')
                except urllib.error.HTTPError as e:
                    status_code = e.code
                    response_body = e.read().decode('utf-8', errors='ignore')
                except urllib.error.URLError:
                    continue

                # Run the response through the YAML Matcher Engine
                is_vulnerable = self.rule_engine.evaluate_response(rule_id, status_code, response_body)
                
                if is_vulnerable:
                    results.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "payload": payload,
                        "status_code": status_code,
                        "matched": True
                    })
                    print(f"  🚨 [BREACH DETECTED] Rule: {rule_id} | Severity: {severity} | Payload: {payload}")
                    
        return results

if __name__ == "__main__":
    # Example usage against a local test server
    tester = APISchemaTester("http://127.0.0.1:5000")
    
    # Boundary test definitions verifying proper 400/422 rejection behavior
    boundary_cases = [
        {
            "name": "Type Mismatch (Integer as String)",
            "payload": {"username": 12345, "email": "test@example.com"},
            "expected_status": [400, 422]
        },
        {
            "name": "Missing Required Field",
            "payload": {"email": "test@example.com"},
            "expected_status": [400, 422]
        },
        {
            "name": "Boundary Length Exceeded",
            "payload": {"username": "A" * 1000, "email": "test@example.com"},
            "expected_status": [400, 422]
        }
    ]

    print("[ANVIL DAST] Running API Contract Boundary Audit...")
    audit_results = tester.test_endpoint_resilience("/api/v1/register", boundary_cases)
    
    for res in audit_results:
        status_str = "PASS" if res["passed"] else "FAIL"
        print(f" -> [{status_str}] {res['case_name']} | Status: {res['status_code']} ({res['notes']})")
        
    print("\n[ANVIL DAST] Running Targeted YAML Attacks...")
    attack_results = tester.execute_yaml_attacks("/api/v1/register")
    if not attack_results:
        print(" -> [PASS] Target resisted all YAML attack rules.")