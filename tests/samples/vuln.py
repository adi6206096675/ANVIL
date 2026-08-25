# tests/samples/vuln.py
import sys
import os

def process_input(user_input):
    print(f"Processing: {user_input}")
    
    # SAST Target: Dangerous function
    if "admin" in user_input:
        os.system("echo 'Admin access granted'") 

    # Fuzzer Target: Intentional crash logic
    if user_input == "' OR 1=1 --":
        print("Fatal Error: SQL Injection payload executed!")
        sys.exit(140) # Simulating a hard crash/breach

    # Fuzzer Target: Memory corruption simulation
    if len(user_input) > 200:
        print("Buffer Overflow!")
        sys.exit(139) # Simulating a segfault

if __name__ == "__main__":
    if len(sys.argv) > 1:
        process_input(sys.argv[1])
    else:
        print("Awaiting input...")