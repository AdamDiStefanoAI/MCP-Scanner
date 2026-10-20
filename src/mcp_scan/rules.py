"""Rule metadata loading and the Finding record used across scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    why: str
    fix: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    name: str
    file: str
    line: int
    evidence: str
    why: str
    fix: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "why": self.why,
            "fix": self.fix,
        }


@dataclass
class RulePack:
    rules: dict[str, Rule] = field(default_factory=dict)
    detection: dict = field(default_factory=dict)

    def finding(self, rule_id: str, file: str, line: int, evidence: str) -> Finding:
        rule = self.rules[rule_id]
        return Finding(
            rule_id=rule.id,
            severity=rule.severity,
            name=rule.name,
            file=file,
            line=max(int(line), 1),
            evidence=" ".join(str(evidence).split())[:200],
            why=rule.why,
            fix=rule.fix,
        )


def load_rules(path: str | Path | None = None) -> RulePack:
    if path is not None:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = (
            resources.files("mcp_scan")
            .joinpath("rules.yaml")
            .read_text(encoding="utf-8")
        )
    data = yaml.safe_load(text) or {}
    pack = RulePack(detection=data.get("detection", {}) or {})
    for raw in data.get("rules", []) or []:
        rule = Rule(
            id=raw["id"],
            name=raw["name"],
            severity=str(raw["severity"]).upper(),
            why=" ".join(str(raw.get("why", "")).split()),
            fix=" ".join(str(raw.get("fix", "")).split()),
        )
        pack.rules[rule.id] = rule
    return pack
