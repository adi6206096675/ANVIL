# tests/samples/sqli.py
import sys

# --- ANVIL INSTRUMENTATION HOOK ---
coverage_set = set()
def trace_calls(frame, event, arg):
    if event == 'line':
        coverage_set.add(frame.f_lineno)
    return trace_calls
sys.settrace(trace_calls)
# ----------------------------------

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    payload = sys.argv[1]
    
    # MOCK DATABASE QUERY
    # This simulates a backend system improperly handling a password input
    query = f"SELECT * FROM users WHERE username = 'admin' AND password = '{payload}'"
    
    # VULNERABILITY: SQL Injection Authentication Bypass
    # If the fuzzer injects an OR statement or a comment tag, the backend is breached.
    if "' OR 1=1" in query or "' OR '1'='1" in query or "' #" in query or "'; --" in query:
        print(f"CRITICAL: Authentication bypassed! Executed Query: {query}", file=sys.stderr)
        print(f"ANVIL_COVERAGE:{list(coverage_set)}")
        # We use Exit Code 140 to signal a Logic/Injection Breach to the Analyst
        sys.exit(140) 
        
    print("Execution normal. Access Denied.")
    print(f"ANVIL_COVERAGE:{list(coverage_set)}")
    sys.exit(0)

if __name__ == "__main__":
    main()