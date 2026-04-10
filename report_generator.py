"""HTML report generator for SaaS Security Posture Dashboard."""
import os
from dataclasses import asdict
from html import escape


def generate_html(summary, scores, findings, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    sev_color = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    def sec_color(score):
        if score >= 80: return "#34c759"
        if score >= 60: return "#ffcc00"
        if score >= 40: return "#ff9500"
        return "#ff3b30"

    # Tool cards
    cards = []
    for i, t in enumerate(sorted(scores, key=lambda x: x.security_score)):
        sc = sec_color(t.security_score)
        util_color = "#34c759" if t.utilization_pct >= 60 else "#ff9500" if t.utilization_pct >= 30 else "#ff3b30"
        redundant_tag = f'<span class="tag red">REDUNDANT with {escape(t.redundant_with)}</span>' if t.is_redundant else ""
        finding_chips = ""
        for f in t.findings[:4]:
            fc = sev_color.get(f.severity, "#888")
            finding_chips += f'<div class="chip" style="border-color:{fc};color:{fc}">{escape(f.title[:60])}</div>'

        cards.append(f"""
        <div class="card" data-score="{t.security_score}">
          <div class="card-head">
            <div class="score-ring" style="--sc:{sc};--pct:{t.security_score}%"><span>{t.security_score}</span></div>
            <div class="card-info">
              <div class="card-name">{escape(t.name)} {redundant_tag}</div>
              <div class="card-cat">{escape(t.category)}</div>
            </div>
            <div class="card-metrics">
              <div class="metric"><span class="mv" style="color:{util_color}">{t.utilization_pct}%</span><span class="ml">utilization</span></div>
              <div class="metric"><span class="mv">${t.annual_cost:,.0f}</span><span class="ml">annual</span></div>
            </div>
          </div>
          <div class="card-findings">{finding_chips}</div>
        </div>""")

    # Savings breakdown
    cost_findings = sorted([f for f in findings if f.savings_annual > 0], key=lambda x: -x.savings_annual)
    savings_rows = "".join(
        f'<tr><td>{escape(f.tool)}</td><td><span class="sv" style="background:{sev_color.get(f.severity,"#888")}">{f.severity}</span></td><td>{escape(f.title)}</td><td class="money">${f.savings_annual:,.0f}</td></tr>'
        for f in cost_findings[:15]
    )

    sec_avg = summary["avg_security_score"]
    sec_avg_color = sec_color(sec_avg)
    savings = summary["potential_annual_savings"]
    spend = summary["total_annual_spend"]

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SaaS Security Posture Dashboard</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#cbd5e1;margin:0;padding:24px;max-width:1300px;margin:auto}}
h1{{color:#34d399;margin:0 0 4px;font-size:26px}}
.sub{{color:#64748b;font-size:13px;margin-bottom:20px}}
.hero{{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:24px;margin-bottom:20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}}
.hblock{{text-align:center;min-width:120px}}
.hblock .n{{font-size:36px;font-weight:900;line-height:1}}
.hblock .l{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;flex:1}}
.s{{background:#020617;border:1px solid #1e293b;border-radius:10px;padding:12px}}
.s .n{{font-size:20px;font-weight:800}} .s .l{{font-size:10px;color:#64748b;text-transform:uppercase}}
h2{{font-size:13px;color:#64748b;text-transform:uppercase;letter-spacing:.8px;margin:28px 0 14px;font-weight:700}}
.card{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:18px;margin-bottom:10px}}
.card-head{{display:flex;align-items:center;gap:16px}}
.score-ring{{width:48px;height:48px;border-radius:50%;background:conic-gradient(var(--sc) var(--pct),#1e293b var(--pct));display:flex;align-items:center;justify-content:center;flex-shrink:0}}
.score-ring span{{background:#0f172a;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:var(--sc)}}
.card-info{{flex:1}}
.card-name{{font-weight:700;font-size:15px;color:#e2e8f0}}
.card-cat{{font-size:11px;color:#64748b}}
.tag{{display:inline-block;font-size:9px;padding:2px 7px;border-radius:4px;margin-left:8px;font-weight:700}}
.tag.red{{background:rgba(255,59,48,.12);color:#ff3b30;border:1px solid rgba(255,59,48,.3)}}
.card-metrics{{display:flex;gap:20px}}
.metric{{text-align:right}}
.mv{{display:block;font-size:16px;font-weight:800}}
.ml{{display:block;font-size:9px;color:#64748b;text-transform:uppercase}}
.card-findings{{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}}
.chip{{font-size:10px;padding:3px 8px;border:1px solid;border-radius:4px;background:rgba(0,0,0,.2)}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}
th{{text-align:left;padding:10px 14px;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;background:#0b111e;border-bottom:1px solid #1e293b}}
td{{padding:8px 14px;font-size:12px;border-bottom:1px solid #131e35}}
.money{{color:#34d399;font-weight:700;font-family:monospace;text-align:right}}
.sv{{color:#000;font-weight:800;font-size:9px;padding:2px 6px;border-radius:8px}}
.footer{{margin-top:30px;color:#334155;font-size:11px;text-align:center}}
</style></head><body>
<h1>SaaS Security Posture Dashboard</h1>
<div class="sub">{summary['total_tools']} tools &middot; ${spend:,.0f}/yr total spend &middot; {summary['total_findings']} findings</div>
<div class="hero">
  <div class="hblock"><div class="n" style="color:{sec_avg_color}">{sec_avg}</div><div class="l">Avg Security Score</div></div>
  <div class="hblock"><div class="n" style="color:#34d399">${savings:,.0f}</div><div class="l">Savings Identified</div></div>
  <div class="hblock"><div class="n" style="color:#ff3b30">{summary['shadow_it_count']}</div><div class="l">Shadow IT</div></div>
  <div class="stats">
    <div class="s"><div class="n">{summary['total_tools']}</div><div class="l">Tools</div></div>
    <div class="s"><div class="n" style="color:#ff3b30">{summary['redundant_tools']}</div><div class="l">Redundant</div></div>
    <div class="s"><div class="n" style="color:#ff3b30">{summary['by_severity'].get('CRITICAL',0)}</div><div class="l">Critical</div></div>
    <div class="s"><div class="n" style="color:#ff9500">{summary['by_severity'].get('HIGH',0)}</div><div class="l">High</div></div>
  </div>
</div>

<h2>Tool Security Scores (worst first)</h2>
{''.join(cards)}

<h2>Cost Savings Opportunities (${savings:,.0f}/yr identified)</h2>
<table><thead><tr><th>Tool</th><th>Severity</th><th>Finding</th><th style="text-align:right">Annual Savings</th></tr></thead>
<tbody>{savings_rows}</tbody></table>

<div class="footer">SaaS Security Posture Dashboard &middot; github.com/CyberEnthusiastic</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
