import io
import zipfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import scan, from_zip


def archive(entries, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as z:
        for name, value in entries.items():
            z.writestr(name, value)
    return out.getvalue()


def test_reports_redact_matched_source():
    example = "synthetic-value-for-test-only"
    report = scan({"app.py": f'password = "{example}"\neval(user_input)\n'})
    assert any(f["rule"] == "SEC001" for f in report["findings"])
    assert example not in str(report)
    assert any(f["line"] == 2 and f["rule"] == "PY001" for f in report["findings"])


def test_zip_root_normalization_and_ignores():
    files, skipped = from_zip(
        archive(
            {
                "repo/README.md": "hello",
                "repo/app.py": "print(1)",
                "repo/node_modules/a.js": "x",
            }
        )
    )
    assert set(files) == {"README.md", "app.py"}
    assert skipped == 1


def test_unsafe_and_compression_bomb_rejected():
    for name in ["../escape.py", "/absolute.py", "C:/bad.py"]:
        with pytest.raises(ValueError):
            from_zip(archive({name: "hello"}))
    with pytest.raises(ValueError):
        from_zip(archive({"f.py": "a" * 100000}, zipfile.ZIP_DEFLATED))
    with pytest.raises(ValueError):
        from_zip(b"not zip")


def test_api_and_body_limits():
    with TestClient(app) as client:
        assert client.get("/api/sample").status_code == 200
        assert (
            client.post("/api/scan", json={"files": {"../oops.py": "x"}}).status_code
            == 422
        )
        report = client.post(
            "/api/scan", json={"files": {"README.md": "# Test"}}
        ).json()
        assert report["files_scanned"] == 1
        assert (
            client.post(
                "/api/scan-zip",
                content=b"x" * 2100001,
                headers={"Content-Type": "application/zip"},
            ).status_code
            == 413
        )


def test_complete_basics_are_not_flagged():
    report = scan(
        {
            "README.md": "# App",
            "LICENSE": "MIT",
            ".gitignore": ".env\n",
            "tests/test_app.py": "assert 1==1",
            ".github/workflows/test.yml": "name: test",
        }
    )
    assert report["findings"] == []
