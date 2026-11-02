#!/usr/bin/env python3
"""
Enterprise Zero Trust Architecture Maturity Evaluator (NIST SP 800-207 & CISA ZTMM v2.0).

Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PILLARS = ["identity", "device", "network", "application", "data"]

MATURITY_TIERS = {
    (0, 49): ("TRADITIONAL", "Perimeter-based security with static credentials and implicit trust zones."),
    (50, 69): ("INITIAL", "Isolated automation, basic MFA, and initial segmentation policies."),
    (70, 89): ("ADVANCED", "Centralized policy enforcement, continuous posture evaluation, and cross-pillar telemetry."),
    (90, 100): ("OPTIMAL", "Fully automated, dynamic, risk-based access control with machine-speed response.")
}


@dataclass
class PillarScore:
    name: str
    score: int  # 0 to 100
    stage: str
    status: str
    strengths: List[str]
    gaps: List[str]


@dataclass
class AssessmentReport:
    framework: str
    timestamp_utc: str
    composite_index: int
    overall_stage: str
    stage_summary: str
    pillars: Dict[str, PillarScore]
    top_recommendations: List[str]


class ZeroTrustEvaluator:
    """Evaluates organization capabilities against NIST SP 800-207 and CISA ZTMM."""

    def __init__(self):
        pass

    @staticmethod
    def classify_stage(score: int) -> str:
        for (low, high), (stage, _) in MATURITY_TIERS.items():
            if low <= score <= high:
                return stage
        return "OPTIMAL" if score > 100 else "TRADITIONAL"

    def evaluate_payload(self, data: Dict[str, Any]) -> AssessmentReport:
        """Parses assessment payload and computes maturity across 5 pillars."""
        framework = data.get("framework", "NIST SP 800-207 / CISA ZTMM v2.0")
        pillars_data = data.get("pillars", {})

        scored_pillars: Dict[str, PillarScore] = {}
        total_score = 0
        top_recs: List[str] = []

        for p in PILLARS:
            p_info = pillars_data.get(p, {})
            score = int(p_info.get("score", 75))
            score = max(0, min(100, score))
            total_score += score
            stage = self.classify_stage(score)

            strengths = list(p_info.get("strengths", []))
            gaps = list(p_info.get("gaps", []))

            if score < 90:
                if p == "identity":
                    gaps.append("Implement phishing-resistant FIDO2 hardware tokens across all privileged identities.")
                elif p == "device":
                    gaps.append("Mandate real-time endpoint health validation prior to session grant.")
                elif p == "network":
                    gaps.append("Enforce micro-segmentation with dynamic East-West traffic inspection.")
                elif p == "application":
                    gaps.append("Deploy API gateways with mutual TLS (mTLS) and workload identity federation.")
                elif p == "data":
                    gaps.append("Implement continuous cryptographic data discovery and automated labeling.")
            else:
                if p == "identity":
                    gaps.append("Enforce continuous adaptive session risk re-authentication on anomalous behavioral telemetry.")
                elif p == "device":
                    gaps.append("Enforce continuous device health attestation with hardware TPM and zero-touch containment.")
                elif p == "network":
                    gaps.append("Advance toward dynamic micro-perimeters with automated isolation and encrypted mesh routing.")
                elif p == "application":
                    gaps.append("Enforce continuous runtime API profiling, automated SBOM validation, and ephemeral credentials.")
                elif p == "data":
                    gaps.append("Automate cryptographic lifecycle management with dynamic data rights and continuous DLP.")

            scored_pillars[p] = PillarScore(
                name=p.capitalize(),
                score=score,
                stage=stage,
                status=p_info.get("status", stage),
                strengths=strengths,
                gaps=gaps
            )
            top_recs.extend(gaps[:1])

        composite = round(total_score / len(PILLARS))
        overall_stage = self.classify_stage(composite)

        summary_desc = ""
        for (low, high), (stage, desc) in MATURITY_TIERS.items():
            if low <= composite <= high:
                summary_desc = desc
                break

        return AssessmentReport(
            framework=framework,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            composite_index=composite,
            overall_stage=overall_stage,
            stage_summary=summary_desc,
            pillars=scored_pillars,
            top_recommendations=top_recs
        )


def format_zt_table(report: AssessmentReport) -> str:
    """Formats ASCII report with visual maturity meters."""
    lines = [
        "==========================================================================",
        "   ZERO TRUST MATURITY EVALUATION (NIST SP 800-207 / CISA ZTMM v2.0)",
        "==========================================================================",
        f"Composite Zero Trust Index: {report.composite_index}/100 [{report.overall_stage}]",
        f"Maturity Classification:    {report.stage_summary}",
        "--------------------------------------------------------------------------",
        "Pillar Maturity Breakdown:"
    ]

    for p_name, p in report.pillars.items():
        # Render visual meter with safe ASCII characters: e.g. [##########] 96%
        filled = int(p.score / 10)
        empty = 10 - filled
        meter = "[" + ("#" * filled) + ("-" * empty) + "]"
        lines.append(f"  * {p.name.ljust(12)}: {meter} {str(p.score).rjust(3)}%  [{p.stage}]")

    lines.append("--------------------------------------------------------------------------")
    lines.append("Key Transformation Directives for Optimal Maturity:")
    for idx, rec in enumerate(report.top_recommendations, 1):
        lines.append(f"  {idx}. {rec}")
    lines.append("==========================================================================")
    return "\n".join(lines)


def get_default_sample_matrix() -> Dict[str, Any]:
    return {
        "framework": "NIST SP 800-207 / CISA ZTMM v2.0",
        "maturity_stage": "ADVANCED_OPTIMAL",
        "pillars": {
            "identity": {
                "score": 96,
                "status": "OPTIMAL",
                "strengths": ["Phishing-resistant FIDO2 MFA", "Centralized Entra ID / Okta Federation"]
            },
            "device": {
                "score": 94,
                "status": "OPTIMAL",
                "strengths": ["Real-time EDR posture signals", "MDM device compliance gating"]
            },
            "network": {
                "score": 98,
                "status": "OPTIMAL",
                "strengths": ["Micro-segmentation overlay", "mTLS 1.3 enforced everywhere"]
            },
            "application": {
                "score": 92,
                "status": "ADVANCED",
                "strengths": ["Container image signing (Cosign)", "Service mesh traffic encryption"]
            },
            "data": {
                "score": 95,
                "status": "OPTIMAL",
                "strengths": ["Automated KMS envelope encryption", "Dynamic DLP policies"]
            }
        }
    }


def main() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="NIST SP 800-207 & CISA ZTMM Zero Trust Maturity Evaluator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python zero_trust_eval.py
  python zero_trust_eval.py --matrix matrix/zero_trust_maturity.json
  python zero_trust_eval.py --input-file samples/enterprise_assessment.json --format json
        """
    )
    parser.add_argument("--matrix", "-m", type=str, help="Path to matrix/zero_trust_maturity.json")
    parser.add_argument("--input-file", "-i", type=str, help="Path to enterprise assessment survey JSON")
    parser.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="Output format")
    parser.add_argument("--output", "-o", type=str, help="Write evaluation output to file")

    args = parser.parse_args()
    evaluator = ZeroTrustEvaluator()

    target_path = args.matrix or args.input_file
    if target_path:
        if not os.path.exists(target_path):
            sys.stderr.write(f"[ERROR] Target file '{target_path}' not found.\n")
            sys.exit(1)
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = get_default_sample_matrix()

    report = evaluator.evaluate_payload(data)

    if args.format == "json":
        out_str = json.dumps(asdict(report), indent=2)
    elif args.format == "markdown":
        md = [
            f"# Zero Trust Maturity Assessment Report",
            f"*Framework*: {report.framework} | *Score*: **{report.composite_index}/100** ({report.overall_stage})",
            "",
            "| Pillar | Score | Stage | Status |",
            "| :--- | :---: | :---: | :--- |"
        ]
        for p in report.pillars.values():
            md.append(f"| **{p.name}** | `{p.score}%` | `{p.stage}` | `{p.status}` |")
        md.append("")
        md.append("### Recommended Roadmap Actions")
        for r in report.top_recommendations:
            md.append(f"- {r}")
        out_str = "\n".join(md)
    else:
        out_str = format_zt_table(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str + "\n")
        print(f"[SUCCESS] Assessment saved to {args.output}")
    else:
        print(out_str)


if __name__ == "__main__":
    main()
