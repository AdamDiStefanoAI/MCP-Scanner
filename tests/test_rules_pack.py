from mcp_scan.rules import SEVERITY_ORDER, load_rules


def test_all_ten_rules_present():
    pack = load_rules()
    expected = {f"MCP-{i:03d}" for i in range(1, 11)}
    assert expected <= set(pack.rules)


def test_rules_have_metadata():
    pack = load_rules()
    for rule in pack.rules.values():
        assert rule.severity in SEVERITY_ORDER
        assert rule.why
        assert rule.fix
        assert rule.name


def test_severity_assignments():
    pack = load_rules()
    assert pack.rules["MCP-001"].severity == "CRITICAL"
    assert pack.rules["MCP-002"].severity == "CRITICAL"
    assert pack.rules["MCP-003"].severity == "HIGH"
    assert pack.rules["MCP-009"].severity == "HIGH"
    assert pack.rules["MCP-006"].severity == "MEDIUM"


def test_detection_hints_loaded(pack):
    assert "bash" in pack.detection["shell_commands"]
    assert "anything" in pack.detection["overbroad_phrases"]
    assert "@modelcontextprotocol/server-filesystem" in pack.detection["known_packages"]
