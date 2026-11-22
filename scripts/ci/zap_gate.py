"""Blocking gate for the ZAP scan: fails on any High risk alert.

Usage: python3 scripts/ci/zap_gate.py REPORT.json

Prints every alert, highest risk first, with the planted flaw it most likely
matches. When GITHUB_STEP_SUMMARY is set, also writes the table there.
"""

import json
import os
import sys

RISKS = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}

# ZAP rule IDs mapped to the planted flaws they can reveal.
# See https://www.zaproxy.org/docs/alerts/ for each rule.
FLAW_BY_RULE = {
    "40018": "F02",  # SQL injection
    "40019": "F02",  # SQL injection - MySQL (time based)
    "40020": "F02",  # SQL injection - Hypersonic
    "40021": "F02",  # SQL injection - Oracle
    "40022": "F02",  # SQL injection - PostgreSQL (time based)
    "40024": "F02",  # SQL injection - SQLite
    "40027": "F02",  # SQL injection - MsSQL
    "40012": "F03",  # Cross site scripting (reflected)
    "40014": "F03",  # Cross site scripting (persistent)
    "40016": "F03",  # Cross site scripting (persistent) - prime
    "40017": "F03",  # Cross site scripting (persistent) - spider
    "40026": "F03",  # Cross site scripting (DOM based)
    "6": "F04",  # Path traversal
    "10010": "F03",  # Cookie no HttpOnly flag
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)

    alerts = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            example = instances[0] if instances else {}
            alerts.append(
                {
                    "risk": alert.get("riskcode", "0"),
                    "rule": alert.get("pluginid", ""),
                    "name": alert.get("alert", alert.get("name", "")),
                    "count": int(alert.get("count", len(instances))),
                    "where": f"{example.get('method', '')} {example.get('uri', '')}".strip(),
                    "param": example.get("param", ""),
                }
            )
    alerts.sort(key=lambda a: (-int(a["risk"]), a["name"]))

    rows = [
        "| Risk | Alert | Rule | Instances | Example | Parameter | Planted flaw |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for a in alerts:
        rows.append(
            f"| {RISKS.get(a['risk'], a['risk'])} | {a['name']} | {a['rule']} | {a['count']} "
            f"| `{a['where']}` | {a['param'] or '-'} | {FLAW_BY_RULE.get(a['rule'], '-')} |"
        )

    high = [a for a in alerts if a["risk"] == "3"]
    flaws = sorted({FLAW_BY_RULE[a["rule"]] for a in high if a["rule"] in FLAW_BY_RULE})
    verdict = (
        f"**Blocked:** {len(high)} High risk alert(s). Planted flaws confirmed: {', '.join(flaws) or 'none'}."
        if high
        else "**Passed:** no High risk alert."
    )

    output = "\n".join(["## ZAP scan", "", verdict, "", *rows, ""])
    print(output)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as target:
            target.write(output + "\n")

    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
