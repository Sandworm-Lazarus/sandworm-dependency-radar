# Development

Python 3.11+; runtime has no Python third-party dependencies. Run `python scripts/validate.py`. Optional shared web viewer checks: `node --test tests/web.test.cjs` (when present). The validation manifest hashes exact source, fixture and viewer bytes. `reports/live-smoke.json` separately records which real upstream engine checks ran; fixtures are labelled synthetic.

Source code belongs to Sandworm-Lazarus. Engines remain upstream projects. The integration uses documented report formats and subprocess interfaces and does not redistribute upstream binaries. Test report parsing, duplicates, ambiguous identities, unknown status, resource limits and failure paths before changing pins or normalizers.

2026-11-11: first cloud-built implementation with read-only adapters, strict JSON imports, normalized reports, baseline comparison, pinned official Linux/amd64 assets, and regression coverage.
