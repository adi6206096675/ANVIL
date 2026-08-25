# engine/rules/parser.py
import os
import yaml
import re

class AnvilRuleEngine:
    """Parses and evaluates declarative YAML attack and test rules."""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.loaded_rules = []
        print(f"[ANVIL RULE ENGINE] Initializing. Scanning '{rules_dir}' for definitions...")
        self._load_rules()

    def _load_rules(self):
        """Loads all .yaml and .yml files from the rules directory."""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        if self._validate_rule(rule):
                            self.loaded_rules.append(rule)
                except Exception as e:
                    print(f"[ANVIL RULE ENGINE] Failed to parse {filename}: {e}")
                    
        print(f"[ANVIL RULE ENGINE] Successfully loaded {len(self.loaded_rules)} rule(s).")

    def _validate_rule(self, rule: dict) -> bool:
        """Ensures the rule has the required architectural structure."""
        required_keys = ["id", "info", "attack", "test"]
        return all(key in rule for key in required_keys)

    def get_all_payloads(self) -> list:
        """Extracts every attack payload from all loaded rules."""
        payloads = set()
        for rule in self.loaded_rules:
            for payload in rule.get("attack", {}).get("payloads", []):
                payloads.add(payload)
        return list(payloads)

    def evaluate_response(self, rule_id: str, status_code: int, response_body: str) -> bool:
        """
        Runs the Test Rules (matchers) against a target's response.
        Returns True if the target is VULNERABLE based on the YAML criteria.
        """
        rule = next((r for r in self.loaded_rules if r["id"] == rule_id), None)
        if not rule:
            return False

        matchers = rule.get("test", {}).get("matchers", [])
        
        for matcher in matchers:
            m_type = matcher.get("type")
            values = matcher.get("values", [])
            
            # Match Status Codes
            if m_type == "status":
                if status_code in values:
                    return True
                    
            # Match Regex Patterns in the output logs/body
            elif m_type == "regex":
                for pattern in values:
                    if re.search(pattern, response_body, re.IGNORECASE):
                        return True

        return False

if __name__ == "__main__":
    # Test the Engine
    engine = AnvilRuleEngine("../../rules")
    print(f"Extracted Payloads: {engine.get_all_payloads()}")
    
    # Simulate a successful attack response
    is_vuln = engine.evaluate_response(
        rule_id="sqli-auth-bypass",
        status_code=500,
        response_body="Fatal error: SQL syntax violation near '''"
    )
    print(f"Vulnerability Confirmed by Rules: {is_vuln}")