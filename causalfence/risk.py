"""Explainable risk verdict: SAFE / MEDIUM / HIGH, with the reasons.

For every finding we look at four factors:
  severity     - how bad the weakness is            (from rules.yml)
  sensitivity  - how valuable the data at the end   (node attribute `sensitivity`)
  exposure     - how open the entry point is        (node `trust` / `auth_type`)
  confidence   - how sure we are                    (edge attribute `confidence`)
Points are added up, scaled by confidence, and turned into a label.
Any finding is at least MEDIUM, so a failed check can never look SAFE.
"""
from dataclasses import dataclass, field

SEVERITY_POINTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SENSITIVITY_POINTS = {"phi": 3, "pii": 2}          # anything else = 1
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.6}
HIGH_AT = 8                                          # scaled points for HIGH


@dataclass
class Item:
    rule: str
    severity: str
    sensitivity: str
    exposure: str
    confidence: str
    points: float
    label: str

    def explain(self) -> str:
        return (f"severity {self.severity} + data {self.sensitivity.upper()} + "
                f"exposure {self.exposure} (confidence {self.confidence}) "
                f"-> {self.label}")


@dataclass
class Verdict:
    label: str
    items: list = field(default_factory=list)

    @property
    def rule_ids(self):
        seen = []
        for i in self.items:
            if i.rule not in seen:
                seen.append(i.rule)
        return seen

    @property
    def failed(self):
        return bool(self.items)

    def headline(self) -> str:
        if not self.items:
            return "Result: SAFE - no findings"
        return (f"Result: {self.label} RISK - FAIL | "
                f"Triggered by: {', '.join(self.rule_ids)}")


def _exposure(G, src):
    d = G.nodes[src]
    if str(d.get("auth_type", "")).upper() == "NONE":
        return "public, no auth", 3
    return "public", 2


def _confidence(G, path):
    rank = ["low", "medium", "high"]
    worst = "high"
    for a, b in zip(path, path[1:]):
        c = str(G.edges[a, b].get("confidence", "high")).lower()
        if c in rank and rank.index(c) < rank.index(worst):
            worst = c
    return worst


def assess(G, result) -> Verdict:
    items = []
    for f in result.findings:
        sink, src = G.nodes[f.path[-1]], f.path[0]
        sens = str(sink.get("sensitivity", "")).lower() or "unknown"
        exposure_name, exposure_pts = _exposure(G, src)
        conf = _confidence(G, f.path)
        raw = (SEVERITY_POINTS.get(f.severity, 1)
               + SENSITIVITY_POINTS.get(sens, 1) + exposure_pts)
        points = raw * CONFIDENCE_FACTOR[conf]
        label = "HIGH" if points >= HIGH_AT else "MEDIUM"
        items.append(Item(f.rule, f.severity, sens, exposure_name,
                          conf, points, label))
    if not items:
        return Verdict("SAFE")
    top = "HIGH" if any(i.label == "HIGH" for i in items) else "MEDIUM"
    return Verdict(top, items)