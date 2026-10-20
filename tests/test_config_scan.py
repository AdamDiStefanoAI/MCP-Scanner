from mcp_scan.config_scan import scan_config


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_shell_command_flagged(pack, fixture):
    findings, servers = scan_config("config_bad.json", fixture("config_bad.json"), pack)
    assert servers == 3
    assert "MCP-001" in rule_ids(findings)


def test_typosquat_and_unpinned_flagged(pack, fixture):
    findings, _ = scan_config("config_bad.json", fixture("config_bad.json"), pack)
    prov = [f for f in findings if f.rule_id == "MCP-009"]
    assert len(prov) >= 2
    assert any("typosquat" in f.evidence for f in prov)


def test_url_without_headers_flagged(pack, fixture):
    findings, _ = scan_config("config_bad.json", fixture("config_bad.json"), pack)
    assert "MCP-005" in rule_ids(findings)


def test_plaintext_env_secret_flagged(pack, fixture):
    findings, servers = scan_config(
        "config_secret_env.json", fixture("config_secret_env.json"), pack
    )
    assert servers == 2
    secrets = [f for f in findings if f.rule_id == "MCP-004"]
    assert len(secrets) == 1


def test_env_reference_not_flagged(pack, fixture):
    findings, _ = scan_config(
        "config_secret_env.json", fixture("config_secret_env.json"), pack
    )
    assert not any(
        f.rule_id == "MCP-004" and '"ref"' in f.evidence for f in findings
    )


def test_clean_config_has_no_findings(pack, fixture):
    findings, servers = scan_config(
        "config_clean.json", fixture("config_clean.json"), pack
    )
    assert servers == 2
    assert findings == []


def test_examples_vulnerable_config(pack):
    from pathlib import Path

    text = (
        Path(__file__).parent.parent / "examples" / "vulnerable_config.json"
    ).read_text(encoding="utf-8")
    findings, servers = scan_config("vulnerable_config.json", text, pack)
    assert servers == 6
    got = rule_ids(findings)
    assert {"MCP-001", "MCP-004", "MCP-005", "MCP-009"} <= got
