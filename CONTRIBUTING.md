# Contributing to MCP-Scanner

Thanks for helping make the MCP ecosystem harder to abuse. The most
valuable contributions, in order:

## New rules

Malicious and sloppy MCP patterns evolve fast. If you have seen one in
the wild:

1. Open an issue describing the pattern and why it is dangerous.
2. If you can, attach a minimal sample server file or config that shows
   it. Redact real secrets.
3. A pull request that adds the detection, a positive fixture, and a
   negative fixture is the fastest path to merge.

Keep severities honest. CRITICAL is reserved for patterns that give an
attacker code execution or a working exfiltration path on their own.

## Bug reports and false positives

False positives are bugs. If the scanner flags a safe server, open an
issue with the minimal file that reproduces it. Detection is heuristic
by design, and every reported false positive makes the heuristics
better.

## Development

```bash
git clone https://github.com/AdamDiStefanoAI/mcp-scanner
cd mcp-scanner
pip install -e . pytest build
pytest -q
```

Guidelines:

- Core scanning stays dependency-light. PyYAML for the rule pack is the
  only runtime dependency; propose new ones in an issue first.
- Every rule change ships with fixtures: one positive, one negative.
- Match the existing code style. No formatter is enforced yet, but keep
  lines readable.
- User-facing text (README, rule explanations) contains no em dashes.

## Conduct

Be direct, be kind, assume good faith. Security tools get built in the
open or they do not get trusted.
