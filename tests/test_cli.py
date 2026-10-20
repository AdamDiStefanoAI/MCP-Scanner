import json
from pathlib import Path

from mcp_scan.cli import main

ROOT = Path(__file__).parent.parent
VULN = ROOT / "examples" / "vulnerable_server.py"
VULN_CONFIG = ROOT / "examples" / "vulnerable_config.json"
SAFE = ROOT / "examples" / "safe_server.py"


def test_exit_code_one_on_critical(capsys):
    rc = main([str(VULN)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "MCP-001" in out
    assert "Summary:" in out


def test_exit_code_zero_on_clean(capsys):
    rc = main([str(SAFE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No findings" in out


def test_vulnerable_config_exit_one():
    assert main([str(VULN_CONFIG)]) == 1


def test_json_format_parses(capsys):
    rc = main([str(VULN), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert data["files_scanned"] == 1
    assert data["summary"]["critical"] >= 1
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert {"MCP-001", "MCP-002", "MCP-005", "MCP-010"} <= rule_ids


def test_sarif_format_parses(capsys):
    rc = main([str(VULN), "--format", "sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "MCP-Scanner"
    assert len(data["runs"][0]["results"]) >= 5


def test_directory_scan(tmp_path, capsys):
    (tmp_path / "server.py").write_text(
        (ROOT / "tests" / "fixtures" / "py_shell_tool.py").read_text()
    )
    rc = main([str(tmp_path)])
    assert rc == 1
