# engine/fuzzers/mutator.py
import random
import string
import os

# Import the new Rule Engine
from engine.rules.parser import AnvilRuleEngine

class AnvilMutator:
    def __init__(self):
        # 1. Combined Industry-Standard Attack Vectors & Magic Numbers
        self.magic_numbers = ["-2147483648", "2147483647", "0", "-1", "65535", "4294967295"]
        self.attack_vectors = {
            "overflows": ["A" * 5000, "%x%x%x%x%x%x%x%x", "%%%s%%%s%%%s"],
            "sqli": ["' OR 1=1 --", "admin' #", "'; DROP TABLE users; --"],
            "cmd_injection": ["; rm -rf /", "& ping -c 10 127.0.0.1", "| cat /etc/passwd"],
            "path_traversal": ["../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\system32\\cmd.exe"],
            "null_byte": ["admin\\x00", "file.txt\\x00.php"]
        }
        
        # 2. Wire in the Declarative YAML Rules
        rule_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../rules"))
        self.rule_engine = AnvilRuleEngine(rule_dir)
        self.yaml_payloads = self.rule_engine.get_all_payloads()
        
        if self.yaml_payloads:
            print(f"[ANVIL MUTATOR] Successfully ingested {len(self.yaml_payloads)} payloads from YAML rules.")

    def bit_flip(self, seed_string: str) -> str:
        """Flips random bits at the byte level to corrupt parsing logic."""
        if not seed_string:
            return ""
        byte_arr = bytearray(seed_string.encode('utf-8', errors='ignore'))
        flip_idx = random.randint(0, len(byte_arr) - 1)
        byte_arr[flip_idx] ^= (1 << random.randint(0, 7))
        return byte_arr.decode('utf-8', errors='ignore')

    def corrupt_structure(self, base_string: str) -> str:
        """Simulates broken JSON or XML syntax."""
        structures = [f'{{"{base_string}": "{base_string}"', f'<{base_string}>', f'[{base_string},,']
        return random.choice(structures)

    def generate_payloads(self, seed: str = "test", count: int = 50) -> list:
        """Generates a highly diverse payload swarm for the Multi-Core engine."""
        payloads = set()
        
        # 1. Inject Magic Numbers
        payloads.update(self.magic_numbers)
        
        # 2. Inject Targeted Attack Vectors
        for category in self.attack_vectors.values():
            payloads.update(category)
            
        # 3. Inject YAML Rule Payloads
        if self.yaml_payloads:
            payloads.update(self.yaml_payloads)
            
        # 4. Inject Boundary Overruns (Massive Buffers)
        for size in [256, 1024, 4096, 10000]:
            payloads.add("A" * size)
            
        # 5. Fill the rest of the batch with mutated seeds
        while len(payloads) < count:
            strategy = random.choice(["flip", "corrupt"])
            if strategy == "flip":
                payloads.add(self.bit_flip(seed))
            else:
                payloads.add(self.corrupt_structure(seed))
                
        return list(payloads)