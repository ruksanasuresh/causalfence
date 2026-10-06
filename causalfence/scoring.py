"""Safety Score Engine: Safety Score = 100 - security penalties."""
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_FILE = Path(__file__).resolve().parent.parent / "rules.yml"


@dataclass
class Score:
    value: int
    label: str
    total_penalty: int

    def __str__(self):
        return f"Safety Score: {self.value}/100 - {self.label}"


def load_scoring(path=RULES_FILE) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["scoring"]


def compute_score(result, scoring: dict = None) -> Score:
    scoring = scoring or load_scoring()
    penalty = result.total_penalty
    value = max(0, scoring["start"] - penalty)

    # Labels are checked from the highest threshold down
    for entry in sorted(scoring["labels"], key=lambda e: e["min"], reverse=True):
        if value >= entry["min"]:
            return Score(value, entry["label"], penalty)
    return Score(value, "UNKNOWN", penalty)