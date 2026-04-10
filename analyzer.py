"""
SaaS Security Posture & Rationalization Dashboard

Analyzes a company's SaaS inventory for:
  1. Security posture — SSO, MFA, SCIM, SOC 2, DPA, review freshness
  2. Cost optimization — utilization %, redundant tools, savings opportunities
  3. Compliance gaps — missing DPA, stale reviews, no encryption
  4. Shadow IT detection — tools without SSO/MFA/SCIM integration
  5. OAuth risk — overly broad scopes, dangerous permissions

Input: JSON inventory of all SaaS tools (see data/saas_inventory.json)
Output: JSON + interactive HTML dashboard with recommendations

Author: Adithya Vasamsetti (CyberEnthusiastic)
License: MIT
"""
import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


BASE_DIR = Path(__file__).parent
STALE_REVIEW_DAYS = 365  # reviews older than this are flagged
LOW_UTILIZATION_THRESHOLD = 0.40  # below 40% = underutilized


@dataclass
class Finding:
    tool: str
    category: str
    finding_type: str   # SECURITY / COST / COMPLIANCE / SHADOW_IT / OAUTH
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    detail: str
    savings_annual: float = 0.0
    recommendation: str = ""


@dataclass
class ToolScore:
    name: str
    category: str
    security_score: int   # 0-100
    utilization_pct: float
    annual_cost: float
    findings: List[Finding] = field(default_factory=list)
    is_redundant: bool = False
    redundant_with: str = ""


class SaaSAnalyzer:
    def __init__(self, inventory_path: str = "data/saas_inventory.json"):
        p = BASE_DIR / inventory_path
        self.data = json.loads(p.read_text(encoding="utf-8"))
        self.tools = self.data["tools"]
        self.tool_scores: List[ToolScore] = []
        self.findings: List[Finding] = []

    def analyze(self) -> (List[ToolScore], List[Finding]):
        for t in self.tools:
            score = self._analyze_tool(t)
            self.tool_scores.append(score)
            self.findings.extend(score.findings)

        self._detect_redundancies()
        return self.tool_scores, self.findings

    def _analyze_tool(self, t: dict) -> ToolScore:
        findings = []
        sec_score = 100

        # --- Security posture checks ---
        if not t.get("sso_enabled"):
            sec_score -= 20
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="SECURITY", severity="HIGH",
                title="SSO not enabled",
                detail=f"{t['name']} does not use SSO. Users authenticate with local passwords.",
                recommendation="Enable SAML/OIDC SSO via your identity provider (Okta/Azure AD).",
            ))

        if not t.get("mfa_enforced"):
            sec_score -= 15
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="SECURITY", severity="HIGH",
                title="MFA not enforced",
                detail=f"{t['name']} does not enforce multi-factor authentication.",
                recommendation="Enforce MFA for all users. If SSO is enabled, MFA at the IdP level suffices.",
            ))

        if not t.get("scim_provisioning"):
            sec_score -= 10
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="SECURITY", severity="MEDIUM",
                title="No SCIM provisioning",
                detail=f"{t['name']} requires manual user provisioning/deprovisioning.",
                recommendation="Enable SCIM to automate joiner/mover/leaver workflows.",
            ))

        if not t.get("soc2_compliant"):
            sec_score -= 15
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="COMPLIANCE", severity="CRITICAL",
                title="Not SOC 2 compliant",
                detail=f"{t['name']} has no SOC 2 Type II report.",
                recommendation="Request SOC 2 report from vendor or replace with compliant alternative.",
            ))

        if not t.get("gdpr_dpa_signed"):
            sec_score -= 10
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="COMPLIANCE", severity="HIGH",
                title="No GDPR DPA signed",
                detail=f"{t['name']} processes data without a signed Data Processing Agreement.",
                recommendation="Execute a DPA with the vendor before next audit.",
            ))

        # Stale security review
        last_review = t.get("last_security_review", "never")
        if last_review == "never":
            sec_score -= 20
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="COMPLIANCE", severity="CRITICAL",
                title="No security review ever conducted",
                detail=f"{t['name']} has never been security-reviewed.",
                recommendation="Conduct a vendor security assessment immediately.",
            ))
        else:
            try:
                review_date = datetime.strptime(last_review, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age_days = (datetime.now(tz=timezone.utc) - review_date).days
                if age_days > STALE_REVIEW_DAYS:
                    sec_score -= 10
                    findings.append(Finding(
                        tool=t["name"], category=t["category"],
                        finding_type="COMPLIANCE", severity="MEDIUM",
                        title=f"Security review is {age_days} days old",
                        detail=f"Last review: {last_review}. Policy requires annual reviews.",
                        recommendation="Schedule a vendor security reassessment.",
                    ))
            except ValueError:
                pass

        # OAuth scope risk
        scopes = t.get("oauth_scopes", [])
        dangerous_scopes = [s for s in scopes if any(d in s.lower() for d in
                           ["full", "admin", "write", "delete", "export", "sharing"])]
        if dangerous_scopes:
            sec_score -= 5 * len(dangerous_scopes)
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="OAUTH", severity="HIGH" if "full" in str(dangerous_scopes).lower() or "admin" in str(dangerous_scopes).lower() else "MEDIUM",
                title=f"Risky OAuth scopes: {', '.join(dangerous_scopes)}",
                detail=f"{t['name']} has {len(dangerous_scopes)} elevated OAuth permissions.",
                recommendation="Review and reduce OAuth scopes to least privilege.",
            ))

        # Shadow IT detection (no SSO + no MFA + no SCIM = likely shadow IT)
        if not t.get("sso_enabled") and not t.get("mfa_enforced") and not t.get("scim_provisioning"):
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="SHADOW_IT", severity="HIGH",
                title="Likely shadow IT — no SSO, no MFA, no SCIM",
                detail=f"{t['name']} is completely disconnected from the identity fabric.",
                recommendation="Integrate with SSO or decommission. Shadow IT is an unmonitored attack surface.",
            ))

        # --- Utilization / Cost checks ---
        licensed = t.get("licensed_seats", 0)
        active = t.get("active_users_30d", 0)
        annual = t.get("annual_cost", 0)
        utilization = active / licensed if licensed > 0 else 1.0

        if utilization < LOW_UTILIZATION_THRESHOLD and licensed > 0:
            wasted_seats = licensed - active
            per_seat_cost = annual / licensed if licensed > 0 else 0
            savings = wasted_seats * per_seat_cost
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="COST", severity="MEDIUM" if utilization > 0.2 else "HIGH",
                title=f"Low utilization: {round(utilization * 100, 1)}% ({active}/{licensed} seats)",
                detail=f"{wasted_seats} unused seats costing ${savings:,.0f}/year.",
                savings_annual=savings,
                recommendation=f"Right-size to {active + 5} seats or consolidate into another tool.",
            ))

        # Risk notes from inventory
        risk_notes = t.get("risk_notes", "")
        if risk_notes:
            findings.append(Finding(
                tool=t["name"], category=t["category"],
                finding_type="SECURITY", severity="MEDIUM",
                title="Vendor note",
                detail=risk_notes,
                recommendation="Address the noted risk in the next review cycle.",
            ))

        sec_score = max(0, min(100, sec_score))

        return ToolScore(
            name=t["name"],
            category=t["category"],
            security_score=sec_score,
            utilization_pct=round(utilization * 100, 1),
            annual_cost=annual,
            findings=findings,
            is_redundant=False,
            redundant_with="",
        )

    def _detect_redundancies(self):
        by_category: Dict[str, List[ToolScore]] = {}
        for ts in self.tool_scores:
            by_category.setdefault(ts.category, []).append(ts)

        for cat, tools in by_category.items():
            if len(tools) > 1:
                # The tool with highest utilization is "primary"; others are candidates
                tools_sorted = sorted(tools, key=lambda x: -x.utilization_pct)
                primary = tools_sorted[0]
                for secondary in tools_sorted[1:]:
                    if secondary.utilization_pct < 50:
                        secondary.is_redundant = True
                        secondary.redundant_with = primary.name
                        self.findings.append(Finding(
                            tool=secondary.name, category=cat,
                            finding_type="COST", severity="HIGH",
                            title=f"Redundant with {primary.name}",
                            detail=f"Both {secondary.name} ({secondary.utilization_pct}% util) and {primary.name} ({primary.utilization_pct}% util) serve '{cat}'. Consolidate.",
                            savings_annual=secondary.annual_cost,
                            recommendation=f"Migrate {secondary.name} users to {primary.name} and cancel the subscription.",
                        ))

    def summary(self) -> dict:
        total_spend = sum(t.annual_cost for t in self.tool_scores)
        total_savings = sum(f.savings_annual for f in self.findings if f.savings_annual > 0)
        avg_sec = sum(t.security_score for t in self.tool_scores) / len(self.tool_scores) if self.tool_scores else 0
        shadow_count = len([f for f in self.findings if f.finding_type == "SHADOW_IT"])
        redundant_count = sum(1 for t in self.tool_scores if t.is_redundant)
        by_type = {}
        by_sev = {}
        for f in self.findings:
            by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        return {
            "total_tools": len(self.tool_scores),
            "total_annual_spend": total_spend,
            "potential_annual_savings": round(total_savings),
            "savings_percent": round(total_savings / total_spend * 100, 1) if total_spend else 0,
            "avg_security_score": round(avg_sec, 1),
            "total_findings": len(self.findings),
            "shadow_it_count": shadow_count,
            "redundant_tools": redundant_count,
            "by_finding_type": by_type,
            "by_severity": by_sev,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="SaaS Security Posture & Rationalization Dashboard"
    )
    parser.add_argument("-i", "--inventory", default="data/saas_inventory.json")
    parser.add_argument("-o", "--output", default="reports/saas_report.json")
    parser.add_argument("--html", default="reports/saas_report.html")
    args = parser.parse_args()

    print("=" * 60)
    print("  [SaaS Security Posture & Rationalization v1.0]")
    print("=" * 60)

    analyzer = SaaSAnalyzer(args.inventory)
    scores, findings = analyzer.analyze()
    summary = analyzer.summary()

    print(f"  Tools analyzed    : {summary['total_tools']}")
    print(f"  Annual spend      : ${summary['total_annual_spend']:,.0f}")
    print(f"  Potential savings : ${summary['potential_annual_savings']:,.0f} ({summary['savings_percent']}%)")
    print(f"  Avg security score: {summary['avg_security_score']}/100")
    print(f"  Total findings    : {summary['total_findings']}")
    print(f"  Shadow IT tools   : {summary['shadow_it_count']}")
    print(f"  Redundant tools   : {summary['redundant_tools']}")
    print(f"  By severity       : {summary['by_severity']}")
    print("=" * 60)

    # Print top recommendations
    print("\n  TOP RECOMMENDATIONS:")
    # Sort: CRITICAL first, then by savings
    top = sorted(findings,
                 key=lambda f: (0 if f.severity == "CRITICAL" else 1 if f.severity == "HIGH" else 2, -f.savings_annual))
    for f in top[:15]:
        sev_c = "\033[91m" if f.severity in ("CRITICAL", "HIGH") else "\033[93m"
        reset = "\033[0m"
        savings_tag = f" (saves ${f.savings_annual:,.0f}/yr)" if f.savings_annual else ""
        print(f"  {sev_c}[{f.severity}]{reset} {f.tool}: {f.title}{savings_tag}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump({
            "summary": summary,
            "tool_scores": [asdict(t) for t in scores],
            "findings": [asdict(f) for f in findings],
        }, fp, indent=2)
    print(f"\n[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, scores, findings, args.html)
    print(f"[+] HTML report: {args.html}")


if __name__ == "__main__":
    main()
