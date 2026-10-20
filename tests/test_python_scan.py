from mcp_scan.python_scan import scan_python


def rule_ids(findings):
    return [f.rule_id for f in findings]


def scan(pack, fixture, name):
    findings, _ = scan_python(name, fixture(name), pack)
    return findings


def test_mcp001_shell_tool_positive(pack, fixture):
    assert "MCP-001" in rule_ids(scan(pack, fixture, "py_shell_tool.py"))


def test_mcp002_exfil_positive(pack, fixture):
    assert "MCP-002" in rule_ids(scan(pack, fixture, "py_exfil.py"))


def test_mcp003_unscoped_positive(pack, fixture):
    assert "MCP-003" in rule_ids(scan(pack, fixture, "py_unscoped.py"))


def test_mcp003_scoped_negative(pack, fixture):
    findings = scan(pack, fixture, "py_scoped.py")
    assert "MCP-003" not in rule_ids(findings)


def test_mcp004_env_tool_positive(pack, fixture):
    assert "MCP-004" in rule_ids(scan(pack, fixture, "py_env_tool.py"))


def test_mcp004_metadata_endpoint_positive(pack, fixture):
    assert "MCP-004" in rule_ids(scan(pack, fixture, "py_metadata.py"))


def test_mcp005_sse_noauth_positive(pack, fixture):
    assert "MCP-005" in rule_ids(scan(pack, fixture, "py_sse_noauth.py"))


def test_mcp005_sse_auth_negative(pack, fixture):
    findings = scan(pack, fixture, "py_sse_auth.py")
    assert findings == []


def test_mcp006_mutating_noschema_positive(pack, fixture):
    assert "MCP-006" in rule_ids(scan(pack, fixture, "py_mutating_noschema.py"))


def test_mcp006_mutating_schema_negative(pack, fixture):
    findings = scan(pack, fixture, "py_mutating_schema.py")
    assert "MCP-006" not in rule_ids(findings)


def test_mcp007_overbroad_positive(pack, fixture):
    assert "MCP-007" in rule_ids(scan(pack, fixture, "py_overbroad.py"))


def test_mcp008_selfmod_positive(pack, fixture):
    assert "MCP-008" in rule_ids(scan(pack, fixture, "py_selfmod.py"))


def test_mcp010_eval_positive(pack, fixture):
    assert "MCP-010" in rule_ids(scan(pack, fixture, "py_eval_tool.py"))


def test_clean_tool_has_no_findings(pack, fixture):
    findings = scan(pack, fixture, "py_clean_tool.py")
    assert findings == []
