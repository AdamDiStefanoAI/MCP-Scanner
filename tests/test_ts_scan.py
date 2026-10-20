from mcp_scan.ts_scan import scan_ts


def rule_ids(findings):
    return [f.rule_id for f in findings]


def test_mcp001_child_process_positive(pack, fixture):
    findings, _ = scan_ts("ts_shell.ts", fixture("ts_shell.ts"), pack)
    assert "MCP-001" in rule_ids(findings)


def test_mcp010_new_function_positive(pack, fixture):
    findings, _ = scan_ts("ts_eval.ts", fixture("ts_eval.ts"), pack)
    assert "MCP-010" in rule_ids(findings)


def test_mcp004_process_env_positive(pack, fixture):
    findings, _ = scan_ts("ts_env.ts", fixture("ts_env.ts"), pack)
    assert "MCP-004" in rule_ids(findings)


def test_clean_ts_has_no_findings(pack, fixture):
    findings, _ = scan_ts("ts_clean.ts", fixture("ts_clean.ts"), pack)
    assert findings == []
