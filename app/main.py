from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .scanner import scan, from_zip, MAX_FILE, MAX_TOTAL, safe_path

STATIC = Path(__file__).resolve().parent.parent / "static"
app = FastAPI(title="RepoCheck API", version="1.0.0")


class Files(BaseModel):
    files: dict[str, str] = Field(min_length=1, max_length=400)


@app.middleware("http")
async def boundary(request: Request, call_next):
    if request.method == "POST":
        body = b""
        async for part in request.stream():
            body += part
            if len(body) > 2100000:
                return JSONResponse(
                    {"detail": "Request limit is 2 MB."}, status_code=413
                )
        request._body = body
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
        }
    )
    if request.url.path == "/":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"
        )
    return response


@app.post("/api/scan")
def scan_json(data: Files):
    total = 0
    try:
        for path, value in data.files.items():
            safe_path(path)
            size = len(value.encode())
            if size > MAX_FILE:
                raise ValueError("Each text file must be under 150 KB.")
            total += size
        if total > MAX_TOTAL:
            raise ValueError("Total text exceeds 6 MB.")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return scan(data.files)


@app.post("/api/scan-zip")
async def scan_zip(request: Request):
    if request.headers.get("content-type") != "application/zip":
        raise HTTPException(415, "Send application/zip bytes.")
    try:
        files, skipped = from_zip(await request.body())
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    result = scan(files)
    result["files_skipped"] = skipped
    return result


@app.get("/api/sample")
def sample():
    # Deliberately weak code to demonstrate findings; never executed.
    return scan(
        {
            "app.py": "def calculate(text):\n    return eval(text)\n\n# Example only\napp.run(debug=True)\n",
            "README.md": "# Example app\nA deliberately incomplete example.",
            "Dockerfile": "FROM python:latest\n",
            ".gitignore": "__pycache__/\n",
        }
    )


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
