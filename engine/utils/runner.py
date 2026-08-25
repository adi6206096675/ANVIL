# engine/utils/runner.py
import subprocess
import time
import ast
import psutil

class AnvilRunner:
    def __init__(self, target_command):
        self.raw_cmd = target_command.split()
        self.memory_limit_mb = 50.0  # The Chokehold limit
        
        # --- THE X-RAY INJECTOR ---
        # Detects if the target is a Python script
        self.is_python_target = "python" in self.raw_cmd[0].lower()
        if self.is_python_target:
            self.target_script = self.raw_cmd[1]
            # This payload intercepts the Python interpreter at runtime.
            # It maps execution lines in memory without modifying the target file.
            self.xray_wrapper = (
                "import sys, runpy\n"
                "cov = set()\n"
                "target = sys.argv[1]\n"
                "def tracer(f, e, a):\n"
                "    if e == 'line' and target in f.f_code.co_filename:\n"
                "        cov.add(f.f_lineno)\n"
                "    return tracer\n"
                "sys.settrace(tracer)\n"
                "try:\n"
                "    sys.argv = sys.argv[1:]\n"  # Trick the target into thinking it was run normally
                "    runpy.run_path(sys.argv[0], run_name='__main__')\n"
                "except SystemExit as e:\n"
                "    sys.exit(e.code if isinstance(e.code, int) else 1)\n"
                "except Exception as e:\n"
                "    print(f'CRITICAL FAULT: {e}')\n"
                "    sys.exit(1)\n"
                "finally:\n"
                "    sys.settrace(None)\n"
                "    print(f'\\nANVIL_COVERAGE:{list(cov)}')\n"
            )

    def execute(self, payload_string, timeout_ms=2500):
        start_time = time.perf_counter()
        is_crash = False
        
        try:
            # Dynamically inject the X-Ray if it's a Python target
            if self.is_python_target:
                full_command = [self.raw_cmd[0], "-c", self.xray_wrapper, self.target_script, payload_string]
            else:
                full_command = self.raw_cmd + [payload_string]
            
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                ps_process = psutil.Process(process.pid)
            except psutil.NoSuchProcess:
                ps_process = None

            # --- THE CHOKEHOLD LOOP ---
            while process.poll() is None:
                elapsed_time = (time.perf_counter() - start_time) * 1000
                
                if elapsed_time > timeout_ms:
                    process.kill()
                    return True, "TIMEOUT", elapsed_time, "Process completely hung.", set()
                
                if ps_process:
                    try:
                        mem_usage_mb = ps_process.memory_info().rss / (1024 * 1024)
                        if mem_usage_mb > self.memory_limit_mb:
                            process.kill()
                            return True, "OOM_KILL", elapsed_time, f"FATAL: Memory limit exceeded ({mem_usage_mb:.2f} MB).", set()
                    except psutil.NoSuchProcess:
                        pass
                        
                time.sleep(0.005)

            stdout, stderr = process.communicate()
            returncode = process.returncode
            
            # If the target returns any non-zero exit code, we classify it as a structural breach
            if returncode != 0:
                is_crash = True
                
            execution_time = (time.perf_counter() - start_time) * 1000
            
            # --- COVERAGE EXTRACTION ---
            executed_lines = set()
            combined_output = stdout + "\n" + stderr
            
            for line in combined_output.splitlines():
                if line.startswith("ANVIL_COVERAGE:"):
                    list_str = line.replace("ANVIL_COVERAGE:", "").strip()
                    try:
                        executed_lines.update(ast.literal_eval(list_str))
                    except (ValueError, SyntaxError):
                        pass

            return is_crash, returncode, execution_time, combined_output, executed_lines

        except Exception as e:
            return True, "SYS_ERROR", 0, str(e), set()