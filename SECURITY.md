# Security Policy

## Reporting a vulnerability in MCP-Scanner

If you find a security problem in MCP-Scanner itself (for example, a
scan target that can crash the scanner or make it execute code), please
do not open a public issue. Report it privately through GitHub's
"Report a vulnerability" button on the Security tab of this repository,
or contact the maintainer via the email on the GitHub profile of
[AdamDiStefanoAI](https://github.com/AdamDiStefanoAI).

Please include a minimal reproduction. Expect an acknowledgment within
a few days.

## Scope notes

- MCP-Scanner is a static scanner. It reads files; it never runs the
  servers it scans, and it makes no network calls.
- Findings about third-party MCP servers you scanned are not
  vulnerabilities in MCP-Scanner. Report those to the server's own
  maintainer, and consider opening a rules issue here if the pattern is
  new.
- The intentionally vulnerable files under `examples/` and
  `tests/fixtures/` are not vulnerabilities. They are test targets.
