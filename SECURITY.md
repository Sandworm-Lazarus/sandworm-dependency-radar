# Security and privacy

Run only on selected local, authorized inputs. Imported JSON and upstream output are untrusted. Sandworm does not run repository code, templates, build scripts or package installation. Engine subprocesses use argument arrays, a minimal environment, no stdin, no shell, a timeout and combined stdout/stderr limits. Errors suppress original engine output. Network/database behavior is documented per CLI.

Limits: JSON 8 MiB, depth 48, 200,000 JSON nodes; 20,000 findings/components. Selected source trees: at most 10,000 files and 256 MiB; symlinks rejected. Trees can change after the initial check; use an isolated, read-only worker/container and resource limits for hostile files. These checks are not an OS sandbox. No Docker daemon/socket access is required.

The report contains package names, versions, relative source names and vulnerability identifiers. Review before sharing. Absolute input source names in Dependency Radar are redacted, but arbitrary package identifiers may still be sensitive. A SHA-256 proves bytes match, not trust or authorship.

No telemetry, credential validation, cloud upload, scheduled job, or server is added by Sandworm. Upstream binaries and databases are installed/cached locally and excluded from source control. Pin updates require rechecking official release metadata and regression/smoke tests. Contact maintainers through a private GitHub security advisory for sensitive reports; do not put secrets in public issues.
