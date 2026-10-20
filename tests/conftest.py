from pathlib import Path

import pytest

from mcp_scan.rules import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="session")
def pack():
    return load_rules()


@pytest.fixture
def fixture():
    def _read(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return _read
