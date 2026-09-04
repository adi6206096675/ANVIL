
# 🛡️ ANVIL (Automated Network & Vulnerability Intensity Laboratory)

> **The Global NCAP for Software.** A production-grade, dual-layer AppSec and Chaos Engineering framework designed for interactive threat hunting and automated CI/CD pipeline enforcement.

[![ANVIL Sentinel](https://github.com/adi6206096675/ANVIL/actions/workflows/anvil-sec.yml/badge.svg)](https://github.com/adi6206096675/ANVIL/actions/workflows/anvil-sec.yml)
![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge&logo=python)
![SARIF Standard](https://img.shields.io/badge/SARIF-v2.1.0-orange?style=for-the-badge)


---

## 🚀 Overview

**ANVIL** is a self-contained, multi-core security orchestration suite that bridges the gap between developer velocity and production safety. Moving beyond standard static checkers, ANVIL subjects applications to deep code audits, live supply-chain vulnerability checks, infrastructure misconfiguration scans, and high-intensity multi-core fuzzing.

It operates under a **Dual-Mode Architecture**:
1. **Manual Threat Hunting Mode (`--mode manual`):** Interactive analysis for security engineers featuring live telemetry, MitM traffic recording, auto-patching, and dark-mode HTML security dashboards.
2. **Gatekeeper CI/CD Mode (`--mode gatekeeper`):** Headless automated execution for enterprise pipelines, producing standardized OASIS SARIF v2.1.0 outputs and enforcing zero-tolerance build-failing gates (`sys.exit(1)`).

---

## ✨ Key Architectural Pillars

* **🔍 Static Application Security Testing (SAST):** AST signature scanning, Android Manifest auditing, and native shared library (`.so`/`.dll`) vulnerability checks.
* **⚡ Multi-Core X-Ray Fuzzer:** Bypasses Python's Global Interpreter Lock (GIL) using parallel process worker swarms to track execution paths and trigger process boundary crashes in milliseconds.
* **💥 ANVIL Xeus (Hydraulic Press):** Environmental chaos engineering engine that starves targets of CPU and memory resources to test application resilience under extreme stress.
* **🌐 Chaos Proxy & DAST:** API contract resilience testing, stateful session/JWT authentication management, and network sabotage proxies (packet dropping and artificial latency injection).
* **📦 Supply Chain (SCA) & IaC Auditing:** Automated dependency manifest scanning (`requirements.txt`, `package.json`) via the OSV database, alongside container security checks (`Dockerfile`, `docker-compose.yml`).
* **🛡️ OASIS SARIF v2.1.0 Compliance:** Native integration with GitHub Security Center and enterprise CI/CD dashboards.

---

## 📁 Project Structure

```text
ANVIL/
├── .github/workflows/      # CI/CD Gatekeeper Pipelines (GitHub Actions)
├── engine/                 
│   ├── auth/               # Stateful session & JWT manager
│   ├── chaos/              # Anvil Xeus (Resource Starvation Engine)
│   ├── dast/               # API contract & boundary testers
│   ├── decompiler/         # APK/ZIP unpackers & binary scanners
│   ├── fuzzers/            # Mutators & Algorithmic Complexity Bombers
│   ├── iac/                # Infrastructure-as-Code auditors
│   ├── proxy/              # MitM traffic recorders & Chaos network proxies
│   ├── sast/               # Static code and manifest scanners
│   ├── sca/                # Supply chain dependency analyzers
│   └── utils/              # Process runners & execution telemetry
├── reporter/               # Analysts, auto-patchers, regression generators, & exporters
├── tests/samples/          # Vulnerable test harnesses for verification
├── reports/                # Generated JSON, HTML dashboards, and SARIF telemetry
├── main.py                 # Master CLI Orchestrator & Dual-Mode Router
└── requirements.txt        # Project dependencies
