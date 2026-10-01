"""A bounded, deterministic hygiene scanner. It never executes scanned code."""

from dataclasses import dataclass, asdict
from pathlib import PurePosixPath, Path
import re
import io
import zipfile

IGNORE = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
}
TEXT = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".env",
    ".txt",
    ".md",
    ".sh",
    ".ini",
    ".cfg",
}
MAX_FILES = 400
MAX_FILE = 150000
MAX_TOTAL = 6000000


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    remediation: str


PATTERNS = [
    (
        "SEC001",
        "high",
        r"(?i)(?:password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[\"\x27][^\"\x27\r\n]{12,}[\"\x27]",
        "Possible hardcoded credential",
        "Use an environment variable. If the value was real and published, rotate it.",
    ),
    (
        "SEC002",
        "high",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Private key marker",
        "Remove the private key from tracked files and rotate it if exposed.",
    ),
    (
        "PY001",
        "medium",
        r"\beval\s*\(",
        "Dynamic evaluation",
        "Avoid evaluating untrusted text. Parse a constrained data format instead.",
    ),
    (
        "PY002",
        "medium",
        r"\bshell\s*=\s*True",
        "Shell-enabled subprocess",
        "Pass an argument list with shell=False and validate arguments.",
    ),
    (
        "NET001",
        "medium",
        r"\bverify\s*=\s*False",
        "TLS verification disabled",
        "Keep certificate verification enabled and fix the trust configuration.",
    ),
    (
        "WEB001",
        "medium",
        r"\bdebug\s*=\s*True",
        "Debug mode enabled",
        "Disable the debug server in production.",
    ),
    (
        "JS001",
        "medium",
        r"\.innerHTML\s*=",
        "HTML injection sink",
        "Prefer textContent for user data; sanitize intentionally supported markup.",
    ),
    (
        "DEP001",
        "low",
        r"(?m)^FROM\s+\S+:latest\s*$",
        "Mutable Docker base tag",
        "Use a versioned base image and update it intentionally.",
    ),
]


def scan(files):
    """files is a mapping of relative paths to text; output excludes source text."""
    findings = []

    def add(rule, severity, path, message, fix, line=0):
        findings.append(Finding(rule, severity, path, line, message, fix))

    paths = list(files)
    names = {PurePosixPath(p).name.lower() for p in paths}
    checks = [
        (
            "DOC001",
            any(n.startswith("readme") for n in names),
            "README",
            "Add purpose, setup, screenshots, limitations and demo instructions.",
        ),
        (
            "DOC002",
            any(n.startswith(("license", "licence")) for n in names),
            "LICENSE",
            "Choose a license you understand and include its full text.",
        ),
        (
            "QA001",
            any(
                "/tests/" in "/" + p
                or PurePosixPath(p).name.startswith("test_")
                or p.endswith((".test.js", ".spec.ts"))
                for p in paths
            ),
            "tests",
            "Add tests for meaningful behavior and failure paths.",
        ),
        (
            "QA002",
            any(p.startswith(".github/workflows/") for p in paths),
            "continuous integration",
            "Run your tests automatically on pushes and pull requests.",
        ),
    ]
    for rule, present, feature, fix in checks:
        if not present:
            add(rule, "low", ".", f"Missing {feature}", fix)
    gitignore = files.get(".gitignore", "")
    if not any(
        line.strip() in (".env", ".env*", ".env.*", "**/.env")
        for line in gitignore.splitlines()
    ):
        add(
            "ENV001",
            "medium",
            ".gitignore",
            "Environment files may be tracked",
            "Ignore .env and local secret files; keep only placeholder .env.example values.",
        )
    for path, content in files.items():
        for rule, severity, pattern, message, fix in PATTERNS:
            if rule.startswith("PY") and not path.endswith(".py"):
                continue
            if rule == "JS001" and not path.endswith((".js", ".ts", ".jsx", ".tsx")):
                continue
            for match in re.finditer(pattern, content):
                add(
                    rule,
                    severity,
                    path,
                    message,
                    fix,
                    content.count("\n", 0, match.start()) + 1,
                )
                if len(findings) >= 1000:
                    break
            if len(findings) >= 1000:
                break
        if len(findings) >= 1000:
            break
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.path, f.line, f.rule))
    counts = {
        level: sum(f.severity == level for f in findings)
        for level in ("high", "medium", "low")
    }
    return {
        "files_scanned": len(files),
        "findings": [asdict(f) for f in findings],
        "counts": counts,
        "truncated": len(findings) >= 1000,
        "notice": "Heuristic findings need review. A clean report does not prove security. No code was executed.",
    }


def safe_path(name):
    path = PurePosixPath(name.replace("\\", "/"))
    if (
        path.is_absolute()
        or ".." in path.parts
        or ":" in name
        or any(ord(c) < 32 for c in name)
        or len(name) > 240
    ):
        raise ValueError("Archive contains an unsafe path.")
    return path


def from_zip(data):
    if len(data) > 2000000:
        raise ValueError("ZIP limit is 2 MB.")
    files, total, skipped = {}, 0, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = [e for e in archive.infolist() if not e.is_dir()]
            if len(entries) > MAX_FILES:
                raise ValueError("Archive has too many files (maximum 400).")
            # GitHub-generated ZIPs wrap all paths in a repository root folder.
            parsed = [safe_path(e.filename) for e in entries]
            prefix = (
                parsed[0].parts[0]
                if parsed
                and all(
                    len(p.parts) > 1 and p.parts[0] == parsed[0].parts[0]
                    for p in parsed
                )
                else None
            )
            for entry, path in zip(entries, parsed):
                if prefix:
                    path = PurePosixPath(*path.parts[1:])
                if any(part in IGNORE for part in path.parts):
                    skipped += 1
                    continue
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Symlinks are not accepted.")
                total += entry.file_size
                if (
                    entry.file_size > MAX_FILE
                    or total > MAX_TOTAL
                    or entry.file_size / max(entry.compress_size, 1) > 100
                ):
                    raise ValueError("Archive exceeds safe decompression limits.")
                if str(path) in files:
                    raise ValueError("Archive contains duplicate paths.")
                if path.suffix.lower() not in TEXT and path.name.lower() not in (
                    "dockerfile",
                    "license",
                    ".gitignore",
                    ".env.example",
                ):
                    skipped += 1
                    continue
                raw = archive.read(entry)
                try:
                    files[str(path)] = raw.decode("utf-8")
                except UnicodeDecodeError:
                    skipped += 1
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise ValueError("Use a valid, unencrypted ZIP archive.")
    if not files:
        raise ValueError("No supported text files were found.")
    return files, skipped


def from_directory(folder):
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError("Provide an existing directory.")
    files, total = {}, 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if (
            any(part in IGNORE for part in rel.parts)
            or path.is_symlink()
            or not path.is_file()
        ):
            continue
        if path.suffix.lower() not in TEXT and path.name.lower() not in (
            "dockerfile",
            "license",
            ".gitignore",
            ".env.example",
        ):
            continue
        # resolve prevents following a symlinked parent outside the selected root.
        if not path.resolve().is_relative_to(root):
            continue
        size = path.stat().st_size
        total += size
        if size > MAX_FILE or total > MAX_TOTAL or len(files) >= MAX_FILES:
            raise ValueError(
                "Directory exceeds limits. Scan a smaller source directory."
            )
        try:
            files[rel.as_posix()] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return files
