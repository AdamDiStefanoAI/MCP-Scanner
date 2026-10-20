"""Code mode (Python): AST scan of MCP server source files.

Covers FastMCP (@mcp.tool()) and low-level mcp.server Server patterns.
Detection is heuristic and deliberately conservative: it flags visible
risk patterns, it does not try to prove intent.
"""

from __future__ import annotations

import ast

from .rules import Finding, RulePack

_SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "commands.getoutput",
}
_NETWORK_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "requests.Session",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "httpx.Client",
    "httpx.AsyncClient",
    "urllib.request.urlopen",
    "aiohttp.ClientSession",
}
_NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib.request"}
_MUTATING_WORDS = (
    "write", "delete", "remove", "exec", "execute", "update", "create",
    "move", "rename", "kill", "drop", "insert", "send", "upload",
)
_VALIDATION_TOKENS = (
    "startswith", "commonpath", "is_relative_to", "resolve(", "allowlist",
    "whitelist", "ALLOWED", "allowed_root", "SAFE_ROOT", "BASE_DIR",
)


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _is_tool(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _dotted(target)
        if name.endswith(".tool") or name == "tool" or name.endswith("list_tools"):
            return True
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            return True
    return False


def _tool_description(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    desc = ast.get_docstring(fn) or ""
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                    desc += " " + str(kw.value.value)
    return desc


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _call_name(call: ast.Call) -> str:
    return _dotted(call.func)


def _open_mode(call: ast.Call) -> str | None:
    mode_node = None
    if len(call.args) >= 2:
        mode_node = call.args[1]
    for kw in call.keywords:
        if kw.arg == "mode":
            mode_node = kw.value
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        return mode_node.value
    return None


def scan_python(path: str, source: str, pack: RulePack) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(rule_id: str, line: int, evidence: str) -> None:
        key = (rule_id, line)
        if key in seen:
            return
        seen.add(key)
        findings.append(pack.finding(rule_id, path, line, evidence))

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], 0

    secret_frags = pack.detection.get("secret_path_fragments", [])
    metadata = pack.detection.get("metadata_endpoints", [])
    config_frags = pack.detection.get("config_file_fragments", [])
    phrases = [p.lower() for p in pack.detection.get("overbroad_phrases", [])]

    functions = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    tools = [fn for fn in functions if _is_tool(fn)]

    network_line: int | None = None
    write_line: int | None = None

    # File-wide call and string checks (MCP-001, 002, 004, 008, 010).
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            seg = ast.get_source_segment(source, node) or name
            if name in _SUBPROCESS_CALLS:
                add("MCP-001", node.lineno, seg)
            elif name.split(".")[0] == "subprocess":
                add("MCP-001", node.lineno, seg)
            if name in ("eval", "exec", "__import__"):
                add("MCP-010", node.lineno, seg)
            if name in _NETWORK_CALLS or name.split(".")[0] in _NETWORK_MODULES and name:
                if network_line is None:
                    network_line = node.lineno
            if name == "open":
                mode = _open_mode(node)
                if mode and any(c in mode for c in "wax+"):
                    if write_line is None:
                        write_line = node.lineno
            if name in ("os.getenv", "os.environ.get") or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "getenv"
            ):
                add("MCP-004", node.lineno, seg)
            if name in ("Path.write_text", "Path.write_bytes") or name.endswith(
                (".write_text", ".write_bytes")
            ):
                if write_line is None:
                    write_line = node.lineno
        if isinstance(node, ast.Subscript) and _dotted(node.value) == "os.environ":
            add("MCP-004", node.lineno, ast.get_source_segment(source, node) or "os.environ[...]")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            for frag in secret_frags:
                if frag in s:
                    add("MCP-004", node.lineno, s)
                    break
            for frag in metadata:
                if frag in s:
                    add("MCP-004", node.lineno, s)
                    break
            lowered = s.lower()
            if "pip install" in lowered or "npm install" in lowered:
                add("MCP-008", node.lineno, s)
            for frag in config_frags:
                if frag in s:
                    add("MCP-008", node.lineno, s)
                    break

    # Exfil path: both capabilities in the same server file (MCP-002).
    if network_line is not None and write_line is not None:
        add(
            "MCP-002",
            network_line,
            "server combines network fetch with local file writes",
        )

    # Network transport without auth (MCP-005).
    has_transport = False
    transport_line = 1
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name.endswith(("SSEServerTransport", "StreamableHTTPServerTransport")):
                has_transport = True
                transport_line = node.lineno
            if name.endswith(".run") or name in ("uvicorn.run",):
                for kw in node.keywords:
                    if kw.arg == "transport" and isinstance(kw.value, ast.Constant):
                        if str(kw.value.value) in ("sse", "streamable-http", "http"):
                            has_transport = True
                            transport_line = node.lineno
    if has_transport:
        lowered_src = source.lower()
        # Code-shaped tokens only: docstrings saying "unauthenticated" must
        # not count as an auth implementation.
        auth_tokens = (
            "authorization", "bearer ", "api_key", "apikey",
            "auth_middleware", "verify_token", "access_token", "requires_auth",
        )
        if not any(tok in lowered_src for tok in auth_tokens):
            add(
                "MCP-005",
                transport_line,
                "network transport started with no authentication check in file",
            )

    # Per-tool checks (MCP-003, 006, 007).
    for fn in tools:
        body_src = ast.get_source_segment(source, fn) or ""

        # MCP-007: overbroad description.
        desc = _tool_description(fn)
        lowered_desc = desc.lower()
        for phrase in phrases:
            if phrase in lowered_desc:
                add("MCP-007", fn.lineno, f'description of {fn.name}: "{phrase}"')
                break

        # MCP-006: mutating tool, untyped or missing parameters.
        args = fn.args
        params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        params = [p for p in params if p.arg not in ("self", "cls", "ctx", "context")]
        mutating = any(w in fn.name.lower() for w in _MUTATING_WORDS)
        if mutating and (not params or all(p.annotation is None for p in params)):
            add(
                "MCP-006",
                fn.lineno,
                f"tool {fn.name} mutates state but its parameters have no type/schema annotations",
            )

        # MCP-003: file access driven by raw tool input, no validation visible.
        param_names = {p.arg for p in params}
        validated = any(tok in body_src for tok in _VALIDATION_TOKENS)
        if not validated:
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    cname = _call_name(node)
                    uses_input = bool(_names_in(node) & param_names) if node.args else False
                    if cname == "open" and uses_input:
                        add(
                            "MCP-003",
                            node.lineno,
                            ast.get_source_segment(source, node) or "open(<tool input path>)",
                        )
                    if cname in ("Path", "pathlib.Path") and uses_input:
                        add(
                            "MCP-003",
                            node.lineno,
                            ast.get_source_segment(source, node) or "Path(<tool input path>)",
                        )

    return findings, 1
