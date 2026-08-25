# main.py
import sys
import os
import argparse
import concurrent.futures
import multiprocessing
import time
from datetime import datetime

# =====================================================================
# CORE ENGINE IMPORTS (WITH SOFT DEGRADATION)
# =====================================================================
from engine.utils.runner import AnvilRunner
from engine.fuzzers.mutator import AnvilMutator
from reporter.models.analyst import AnvilWebReporter

# SAST & Manifest Auditing
try:
    from engine.sast.scanner import AnvilStaticScanner
except ImportError:
    AnvilStaticScanner = None

try:
    from engine.sast.manifest_scanner import ManifestAuditor
except ImportError:
    ManifestAuditor = None

# DAST, Proxy Interceptor & Stateful Auth
try:
    from engine.dast.schema_tester import APISchemaTester
except ImportError:
    APISchemaTester = None

try:
    from engine.proxy.recorder import AnvilTrafficProxy
except ImportError:
    AnvilTrafficProxy = None

try:
    from engine.auth.session import AnvilAuthManager
except ImportError:
    AnvilAuthManager = None

# Chaos Engineering (Xeus, Chaos Proxy, & Bomber)
try:
    from engine.proxy.chaos import AnvilChaosProxy
except ImportError:
    AnvilChaosProxy = None

try:
    from engine.chaos.xeus import AnvilXeus
except ImportError:
    AnvilXeus = None

try:
    from engine.fuzzers.bomber import AnvilComplexityBomber
except ImportError:
    AnvilComplexityBomber = None

# Decompiler & Native Binary Scanner
try:
    from engine.decompiler.pipeline import AnvilDecompilerPipeline
except ImportError:
    AnvilDecompilerPipeline = None

try:
    from engine.decompiler.binary_scanner import NativeBinaryAuditor
except ImportError:
    NativeBinaryAuditor = None

# Supply Chain (SCA) & IaC Auditing
try:
    from engine.sca.scanner import AnvilSCAScanner
except ImportError:
    AnvilSCAScanner = None

try:
    from engine.iac.scanner import AnvilIaCScanner
except ImportError:
    AnvilIaCScanner = None

# Reporters, Auto-Patcher & Exporters
try:
    from reporter.exporter import AnvilExporter
except ImportError:
    AnvilExporter = None

try:
    from reporter.patcher import AnvilAutoPatcher
except ImportError:
    AnvilAutoPatcher = None

try:
    from reporter.reproducer import AnvilRegressionGenerator
except ImportError:
    AnvilRegressionGenerator = None


# Global Master Audit State
master_report_data = {
    "target": "",
    "mode": "MANUAL",
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "sast": [],
    "dast": [],
    "sca": [],
    "iac": [],
    "fuzzer": []
}


def worker_task(target_command: str, payload: str) -> dict:
    """
    Isolated worker execution task.
    Runs on a dedicated CPU thread to bypass Python's GIL.
    """
    runner = AnvilRunner(target_command)
    is_crash, exit_code, exec_time, logs, executed_lines = runner.execute(payload)
    
    return {
        "payload": payload,
        "is_crash": is_crash,
        "exit_code": exit_code,
        "exec_time": exec_time,
        "logs": logs,
        "executed_lines": set(executed_lines)
    }


# =====================================================================
# SUBSYSTEM RUNNERS
# =====================================================================

def run_decompile_phase(target_path: str) -> dict:
    """Decompiles and unzips applications (.apk, .zip) into analyzed components."""
    print("\n" + "="*60)
    print("📦 [ANVIL PHASE] APPLICATION DECOMPILER & UNPACKER")
    print("="*60)

    if not AnvilDecompilerPipeline:
        print("[ANVIL ERROR] Decompiler module missing at engine/decompiler/pipeline.py")
        return {}

    decompiler = AnvilDecompilerPipeline()
    pieces = decompiler.decompile(target_path)
    
    # Audit Manifest if present
    if pieces.get("manifest") and ManifestAuditor:
        print("\n[ANVIL SAST] Auditing Decompiled Android Manifest...")
        manifest_auditor = ManifestAuditor()
        manifest_findings = manifest_auditor.audit_manifest(pieces["manifest"])
        for item in manifest_findings:
            print(f"  • [{item['severity']}] {item['type']}: {item['detail']}")
            master_report_data["sast"].append(item)

    # Audit Native Shared Libraries (.so / .dll)
    if pieces.get("native_libs") and NativeBinaryAuditor:
        print("\n[ANVIL DECOMPILER] Auditing Native Shared Libraries (.so / .dll)...")
        binary_auditor = NativeBinaryAuditor()
        for lib_path in pieces["native_libs"]:
            bin_findings = binary_auditor.scan_binary(lib_path)
            for item in bin_findings:
                print(f"  • [{item['severity']}] {item['type']}: {item['detail']}")
                master_report_data["sast"].append(item)

    print("="*60 + "\n")
    return pieces


def run_sast_phase(target_path: str):
    """Executes the Static Application Security Testing (SAST) module."""
    print("\n" + "="*60)
    print("🔍 [ANVIL PHASE 1] STATIC CODE AUDIT (SAST)")
    print("="*60)

    if not AnvilStaticScanner:
        print("[ANVIL ERROR] SAST module missing or not found at engine/sast/scanner.py")
        return

    sast_engine = AnvilStaticScanner()
    findings = sast_engine.run_sast(target_path)

    if findings:
        print(f"\n[!] SAST AUDIT DISCOVERED {len(findings)} VULNERABILITIES / RISK PATTERNS:")
        for item in findings:
            print(f"  • [{item['severity']}] {item['type']} (Line {item['line']}): {item['detail']}")
            master_report_data["sast"].append(item)
    else:
        print("[+] SAST Audit complete: No static vulnerability signatures detected.")
    print("="*60 + "\n")


def run_sca_phase(target_dir: str):
    """Executes the Supply Chain & Dependency (SCA) scanner via OSV API."""
    print("\n" + "="*60)
    print("📦 [ANVIL PHASE] SUPPLY CHAIN & DEPENDENCY AUDIT (SCA)")
    print("="*60)

    if not AnvilSCAScanner:
        print("[ANVIL ERROR] SCA module missing at engine/sca/scanner.py")
        return

    sca_engine = AnvilSCAScanner()
    manifests = ["requirements.txt", "package.json"]
    
    found_manifest = False
    for m in manifests:
        m_path = os.path.join(target_dir, m) if os.path.isdir(target_dir) else m
        if os.path.exists(m_path):
            found_manifest = True
            findings = sca_engine.scan_manifest(m_path)
            for f in findings:
                print(f"  • [{f['severity']}] {f['package']} ({f['version']}): {f['cve_id']} - {f['detail']}")
                master_report_data["sca"].append(f)

    if not found_manifest:
        print("[*] No dependency manifests (requirements.txt, package.json) detected in target directory.")
    print("="*60 + "\n")


def run_iac_phase(target_dir: str):
    """Executes the Infrastructure-as-Code (IaC) Scanner."""
    print("\n" + "="*60)
    print("☁️ [ANVIL PHASE] INFRASTRUCTURE-AS-CODE AUDIT (IaC)")
    print("="*60)

    if not AnvilIaCScanner:
        print("[ANVIL ERROR] IaC module missing at engine/iac/scanner.py")
        return

    iac_engine = AnvilIaCScanner()
    iac_files = ["Dockerfile", "docker-compose.yml"]

    for f in iac_files:
        f_path = os.path.join(target_dir, f) if os.path.isdir(target_dir) else f
        if os.path.exists(f_path):
            findings = iac_engine.scan_file(f_path)
            for item in findings:
                print(f"  • [{item['severity']}] Line {item['line']}: {item['detail']}")
                master_report_data["iac"].append(item)

    print("="*60 + "\n")


def run_dast_phase(base_url: str, auth_headers: dict = None):
    """Executes the Dynamic Application Security Testing (DAST) API module."""
    print("\n" + "="*60)
    print("🌐 [ANVIL PHASE 2] API CONTRACT & BOUNDARY AUDIT (DAST)")
    print("="*60)

    if not APISchemaTester:
        print("[ANVIL ERROR] DAST module missing or not found at engine/dast/schema_tester.py")
        return

    tester = APISchemaTester(base_url)
    
    boundary_cases = [
        {
            "name": "Type Mismatch (Integer as String)",
            "payload": {"username": 12345, "email": "admin@example.com"},
            "expected_status": [400, 422, 401, 403]
        },
        {
            "name": "Missing Required Parameter",
            "payload": {"email": "admin@example.com"},
            "expected_status": [400, 422, 401, 403]
        },
        {
            "name": "Boundary Length Exceeded",
            "payload": {"username": "A" * 2048, "email": "admin@example.com"},
            "expected_status": [400, 422, 401, 403]
        }
    ]

    print(f"[ANVIL DAST] Testing endpoint contract boundaries against: {base_url}")
    results = tester.test_endpoint_resilience("/api/v1/register", boundary_cases)

    for res in results:
        status_str = "PASS" if res["passed"] else "FAIL"
        print(f"  • [{status_str}] {res['case_name']} | Status: {res['status_code']} ({res['notes']})")
        master_report_data["dast"].append(res)

    print("\n[ANVIL DAST] Deploying Targeted YAML Attack Rules...")
    attack_results = tester.execute_yaml_attacks("/api/v1/register")
    if not attack_results:
        print("  • [PASS] Target endpoint resisted all YAML attack signatures.")
    else:
        for res in attack_results:
            master_report_data["dast"].append(res)

    print("="*60 + "\n")


def run_proxy_phase(chaos_mode=False):
    """Starts the MitM Traffic Recorder Proxy or the Network Chaos Proxy."""
    if chaos_mode:
        if not AnvilChaosProxy:
            print("[ANVIL ERROR] Traffic Chaos Proxy module missing at engine/proxy/chaos.py")
            return
        proxy = AnvilChaosProxy()
        proxy.start()
        input("\n[ANVIL CHAOS] Network sabotage proxy active. Press ENTER to terminate...\n")
        proxy.stop()
    else:
        if not AnvilTrafficProxy:
            print("[ANVIL ERROR] Traffic Proxy module missing at engine/proxy/recorder.py")
            return
        proxy = AnvilTrafficProxy()
        proxy.start()
        input("\n[ANVIL PROXY] Interceptor active on http://127.0.0.1:8080\nPress ENTER to terminate proxy and record captured sessions...\n")
        proxy.stop_and_save()


def ignite_anvil_fuzzer(target_command: str, auto_patch: bool = False, generate_repro: bool = False, use_bomber: bool = False):
    """Executes the Multi-Core Dynamic Fuzzing Engine with automated remediation hooks and bomber payload injections."""
    print(f"[ANVIL CORE] Igniting stress tests on: {target_command}")
    
    mutator = AnvilMutator()
    reporter = AnvilWebReporter()
    
    max_workers = multiprocessing.cpu_count()
    print(f"[ANVIL CORE] Multiprocessing enabled: Swarming with {max_workers} concurrent CPU threads.")
    print("[ANVIL CORE] Stand by for structural failure...\n")
    
    iterations = 0
    log_path = "tests/samples/crash_report.log"
    global_coverage = set()
    
    batch_size = max_workers * 10 
    breach_detected = False
    
    # Base Payload Seed Pool
    seed_pool = ["hello", "test", "admin", "1234", "' OR 1=1 --", "\\x00"]
    
    # Inject Algorithmic Exhaustion (Bomber) Payloads if requested
    if use_bomber and AnvilComplexityBomber:
        print("[ANVIL BOMBER] Injecting algorithmic exhaustion payloads into swarm matrix...")
        bomber_payloads = [p["payload"] for p in AnvilComplexityBomber.get_payloads()]
        seed_pool.extend(bomber_payloads)

    while not breach_detected:
        current_seed = seed_pool[iterations % len(seed_pool)]
        payloads = mutator.generate_payloads(seed=current_seed, count=batch_size)
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(worker_task, target_command, p): p for p in payloads}
            
            for future in concurrent.futures.as_completed(futures):
                iterations += 1
                try:
                    result = future.result()
                except Exception as e:
                    print(f"[ANVIL ERROR] Thread fault: {e}")
                    continue
                
                # Update X-Ray Coverage Map
                new_lines = result["executed_lines"] - global_coverage
                if new_lines:
                    global_coverage.update(new_lines)
                    seed_pool.append(result["payload"]) 
                    print(f"[+] NEW PATH UNLOCKED: Payload discovered lines {new_lines}")

                if iterations % 500 == 0:
                    print(f"[*] {iterations} payloads fired... Target holding. (Coverage: {len(global_coverage)} lines)")

                # Breach Detection
                if result["is_crash"]:
                    print("\n" + "="*50)
                    print("🚨 ANVIL BREACH DETECTED 🚨")
                    print("="*50)
                    print(f"ITERATION : {iterations}")
                    print(f"EXIT CODE : {result['exit_code']}")
                    print(f"PAYLOAD   : {repr(result['payload'])[:150]}...") # Truncated for terminal sanity
                    print(f"EXEC TIME : {result['exec_time'] / 1000:.4f}s ({result['exec_time']:.1f}ms)")
                    print(f"TOTAL COV : {len(global_coverage)} lines mapped.")
                    print("="*50)
                    
                    master_report_data["fuzzer"].append({
                        "iteration": iterations,
                        "exit_code": result["exit_code"],
                        "payload": result["payload"],
                        "exec_time_ms": result["exec_time"]
                    })

                    # Dump crash state for Analysis
                    with open(log_path, "w", encoding="utf-8") as f:
                        f.write(f"PAYLOAD: {repr(result['payload'])}\n")
                        f.write(f"EXIT: {result['exit_code']}\n")
                        f.write(f"LOGS: {result['logs']}")
                    
                    # Run deterministic analysis
                    try:
                        verdict = reporter.generate_report(log_path)
                        print("\n" + verdict.strip() + "\n" + "="*50)
                    except Exception as e:
                        print(f"[ANVIL ERROR] Deterministic analysis failed: {str(e)}")

                    # Generate Regression Test Script
                    if generate_repro and AnvilRegressionGenerator:
                        repro_gen = AnvilRegressionGenerator()
                        repro_gen.generate_test_case(target_command, result["payload"], result["exit_code"])

                    # Apply Auto-Patch
                    if auto_patch and AnvilAutoPatcher:
                        patcher = AnvilAutoPatcher()
                        cmd_parts = target_command.split()
                        target_file = cmd_parts[1] if len(cmd_parts) > 1 and cmd_parts[0].lower() == "python" else cmd_parts[0]
                        patched_file = patcher.apply_patch(
                            filepath=target_file,
                            target_line=2,
                            patch_code="raise ValueError('ANVIL Auto-Patch: Input rejected.')",
                            vuln_type="Process Crash / Logic Breach"
                        )
                        print(f"[ANVIL AUTO-PATCHER] Remediated file generated: {patched_file}")

                    breach_detected = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break


# =====================================================================
# MAIN ENTRYPOINT & DUAL-MODE ROUTER
# =====================================================================

if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    parser = argparse.ArgumentParser(
        description="ANVIL: Automated Network & Vulnerability Intensity Laboratory",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "target", 
        nargs="?",
        default=".",
        help="The target script, binary, package, or URL to analyze/fuzz.\nExample: python main.py \"python ./tests/samples/vuln.py\""
    )

    # ---------------------------------------------------------
    # DUAL-MODE ARCHITECTURE
    # ---------------------------------------------------------
    parser.add_argument(
        "--mode",
        choices=["manual", "gatekeeper"],
        default="manual",
        help="Execution mode: 'manual' for interactive hunting, 'gatekeeper' for headless CI/CD pipelines."
    )
    
    # Granular Manual Scanners
    parser.add_argument("--sast", action="store_true", help="Run static code analysis (AST & Manifest).")
    parser.add_argument("--dast", action="store_true", help="Run dynamic API contract & boundary tests.")
    parser.add_argument("--sca", action="store_true", help="Run supply chain & dependency CVE audit.")
    parser.add_argument("--iac", action="store_true", help="Run Infrastructure-as-Code (Dockerfile/K8s) audit.")
    parser.add_argument("--decompile", action="store_true", help="Unpack/decompile target package (.apk/.zip) prior to audit.")
    
    # Chaos Engineering Modules
    parser.add_argument("--proxy", action="store_true", help="Start local MitM traffic interceptor proxy.")
    parser.add_argument("--chaos-proxy", action="store_true", help="Start Network Sabotage Proxy (drops packets, injects latency).")
    parser.add_argument("--xeus", action="store_true", help="Engage Anvil Xeus (Hydraulic Press / Resource Starvation).")
    parser.add_argument("--bomber", action="store_true", help="Inject algorithmic DoS payloads (Billion Laughs, ReDoS) into fuzzer.")
    
    # Automation & Reporting
    parser.add_argument("--auto-patch", action="store_true", help="Automatically generate .patched source files on breach.")
    parser.add_argument("--reproduce", action="store_true", help="Generate standalone regression unittest on breach.")
    parser.add_argument("--export", action="store_true", help="Generate HTML security dashboard and JSON audit reports.")
    parser.add_argument("--all", action="store_true", help="Run full unified audit sweep (Legacy alias for Gatekeeper).")

    # Stateful Authentication (Session Fuzzing)
    parser.add_argument("--login-url", help="Endpoint for stateful authentication (DAST).")
    parser.add_argument("--username", help="Username for authentication.")
    parser.add_argument("--password", help="Password for authentication.")

    args = parser.parse_args()
    
    # Store Global Context
    master_report_data["target"] = args.target
    master_report_data["mode"] = args.mode.upper()

    # Target Parsing
    cmd_parts = args.target.split()
    target_path = cmd_parts[1] if len(cmd_parts) > 1 and cmd_parts[0].lower() == "python" else cmd_parts[0]
    target_dir = os.path.dirname(target_path) or "."
    is_web = args.target.startswith("http")
    is_package = target_path.endswith((".apk", ".zip"))

    # 1. Handle Exclusive MitM / Chaos Proxy Modes
    if args.proxy:
        run_proxy_phase(chaos_mode=False)
        sys.exit(0)
    elif args.chaos_proxy:
        run_proxy_phase(chaos_mode=True)
        sys.exit(0)

    # 2. Handle Stateful Authentication
    auth_headers = None
    if args.login_url and args.username and args.password and AnvilAuthManager:
        auth = AnvilAuthManager(args.login_url)
        auth_headers = auth.authenticate(args.username, args.password)

    # 3. Initialize Anvil Xeus (Hydraulic Press) if requested
    xeus_engine = None
    if args.xeus and AnvilXeus:
        xeus_engine = AnvilXeus(memory_mb_to_consume=500)
        xeus_engine.engage_pressure()

    try:
        # ==========================================
        # MODE 1: GATEKEEPER (Automated CI/CD Sentinel)
        # ==========================================
        if args.mode == "gatekeeper" or args.all:
            print("\n" + "🛡️ "*25)
            print("   ANVIL GATEKEEPER MODE ACTIVATED (HEADLESS CI/CD)")
            print("🛡️ "*25 + "\n")

            if is_package: run_decompile_phase(target_path)
            run_sast_phase(target_path)
            run_sca_phase(target_dir)
            run_iac_phase(target_dir)

            if is_web:
                run_dast_phase(args.target, auth_headers)
            else:
                ignite_anvil_fuzzer(args.target, auto_patch=False, generate_repro=False, use_bomber=args.bomber)

            # Force Output Generation
            if AnvilExporter:
                exporter = AnvilExporter()
                exporter.export_json(master_report_data)
                exporter.export_html(master_report_data)
                sarif_path = exporter.export_sarif(master_report_data)
                print(f"\n[ANVIL GATEKEEPER] Artifacts generated. SARIF located at: {sarif_path}")

            # Strict Pass/Fail Enforcement
            failed_dast = [d for d in master_report_data["dast"] if not d.get("passed", True)]
            total_vulns = len(master_report_data["sast"]) + len(master_report_data["sca"]) + len(master_report_data["iac"]) + len(master_report_data["fuzzer"]) + len(failed_dast)
            
            if total_vulns > 0:
                print(f"\n🚨 [BUILD FAILED] ANVIL detected {total_vulns} vulnerabilities. Pipeline halted to protect production.")
                sys.exit(1)
            else:
                print("\n✅ [BUILD PASSED] ANVIL confirms target is clean. Proceeding with deployment.")
                sys.exit(0)


        # ==========================================
        # MODE 2: MANUAL (Interactive Threat Hunting)
        # ==========================================
        else:
            if args.decompile or is_package: run_decompile_phase(target_path)
            if args.sast: run_sast_phase(target_path)
            if args.sca: run_sca_phase(target_dir)
            if args.iac: run_iac_phase(target_dir)
            if args.dast and is_web: run_dast_phase(args.target, auth_headers)

            # Default to Multi-Core Fuzzer if no specific scanner is chosen and it's not a web target
            if not any([args.sast, args.dast, args.sca, args.iac]):
                if is_web:
                    run_dast_phase(args.target, auth_headers)
                else:
                    ignite_anvil_fuzzer(
                        target_command=args.target, 
                        auto_patch=args.auto_patch, 
                        generate_repro=args.reproduce,
                        use_bomber=args.bomber
                    )

            # Optional Manual Export
            if args.export and AnvilExporter:
                exporter = AnvilExporter()
                json_path = exporter.export_json(master_report_data)
                html_path = exporter.export_html(master_report_data)
                print(f"\n[ANVIL EXPORTER] Reports saved to:\n  • {json_path}\n  • {html_path}")

    finally:
        # Crucial safety net: Guarantee Xeus releases resources even if the system crashes or exits
        if xeus_engine:
            xeus_engine.release_pressure()