# tests/samples/leak.py
import sys
import time

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
    
    # VULNERABILITY: Unbounded Memory Allocation (Memory Leak)
    # This list will grow forever, eating your system's RAM
    memory_hog = [] 
    
    print("Beginning processing loop...", file=sys.stderr)
    
    while True:
        # Allocate roughly 1MB of memory per loop iteration
        memory_hog.append("A" * (1024 * 1024)) 
        time.sleep(0.05) # Delay so the system doesn't instantly freeze

if __name__ == "__main__":
    main()