# Zero Trust Posture Matrix 🌐

[![Zero Trust Maturity](https://img.shields.io/badge/Maturity%20Index-95%2F100%20(Optimal)-brightgreen?style=flat-square&logo=cisco&logoColor=white)](https://github.com/GarciaVillenaLuis/zero-trust-posture-matrix)
[![Standard](https://img.shields.io/badge/Framework-NIST%20SP%20800--207%20%7C%20CISA%20ZTMM-blue?style=flat-square&logo=nist&logoColor=white)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Continuous%20Adaptive%20Verification-orange?style=flat-square)](https://ismsforum.es/)

Continuous verification engine and maturity assessment framework aligned with **NIST SP 800-207** and **CISA Zero Trust Maturity Model (ZTMM) v2.0**.

Engineered and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🏛️ The 5 Core Zero Trust Pillars Assessed

This engine measures enterprise maturity across the 5 canonical dimensions defined by CISA & NIST:

```text
 +-----------------------------------------------------------------------------------+
 |                        NIST SP 800-207 CONTROL PLANE                              |
 |               Policy Engine (PE)  <--->  Policy Administrator (PA)                |
 +-----------------------------------------------------------------------------------+
             │                      │                   │                   │
     [ 1. IDENTITY ]        [ 2. DEVICE ]       [ 3. NETWORK ]      [ 4. APP & WORKLOAD ]
   Phishing-Resistant      Continuous EDR      Micro-segmentation   Workload Identity &
   FIDO2 & Conditional     Health Signals &    & TLS 1.3 Overlay    Mutual TLS Service
        Access            Hardware Tokens                           Mesh Federation
             └──────────────────────┴───────────────────┴───────────────────┘
                                            │
                                    [ 5. DATA PILLAR ]
                             Dynamic KMS Envelope Encryption &
                             Automated Data Classification Labeling
```

### Maturity Stages
1. **Traditional**: Perimeter-centric defences, static credentials, and broad network segment access.
2. **Initial**: Isolated automation, preliminary MFA, and reactive policy enforcement.
3. **Advanced**: Centralized policy engines, cross-pillar telemetry correlation, and adaptive risk-scoring.
4. **Optimal**: Continuous verification, dynamic context-aware policy enforcement, and machine-speed mitigation.

---

## 🚀 Quick Start & CLI Usage

### Available Flags & Parameters

```bash
python zero_trust_eval.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--matrix FILE` | `string` | Evaluate repository telemetry matrix (`matrix/zero_trust_maturity.json`) |
| `--input-file FILE` | `string` | Ingest external enterprise Zero Trust survey JSON |
| `--format FMT` | `choice` | Output format: `table` (ASCII meters), `json`, or `markdown` |
| `--output FILE` | `string` | Save output report to disk |

---

## 💻 Usage Examples

### 1. Run local Zero Trust posture evaluation
```bash
python zero_trust_eval.py --format table
```
**Sample Output:**
```text
==========================================================================
   ZERO TRUST MATURITY EVALUATION (NIST SP 800-207 / CISA ZTMM v2.0)
==========================================================================
Composite Zero Trust Index: 95/100 [OPTIMAL]
Maturity Classification:    Fully automated, dynamic, risk-based access control with machine-speed response.
--------------------------------------------------------------------------
Pillar Maturity Breakdown:
  • Identity    : [█████████░]  96%  [OPTIMAL]
  • Device      : [█████████░]  94%  [OPTIMAL]
  • Network     : [█████████░]  98%  [OPTIMAL]
  • Application : [█████████░]  92%  [OPTIMAL]
  • Data        : [█████████░]  95%  [OPTIMAL]
--------------------------------------------------------------------------
Key Transformation Directives for Optimal Maturity:
  1. Continual verification of session tokens with automated revocation.
==========================================================================
```

### 2. Export Markdown report for executive stakeholders
```bash
python zero_trust_eval.py --input-file samples/enterprise_assessment.json --format markdown -o zt_report.md
```

---

## 🧪 Unit Testing

Execute the automated test suite with standard `unittest`:

```bash
python -m unittest tests/test_zero_trust_eval.py
```

---

## 📜 Continuous Maturity Ledger

Real-time Zero Trust maturity telemetry and cryptographic audit hashes are tracked in:
- [`matrix/zero_trust_maturity.json`](./matrix/zero_trust_maturity.json)
