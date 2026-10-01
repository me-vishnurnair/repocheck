# RepoCheck, explained simply

## The idea

A defensive repository hygiene checker with a reusable Python engine, local CLI and HTTP API.

Start by running the application and completing one real action. Then follow the files below. You do not need to memorize the code; you need to explain how data moves and what can fail.

## Where to look

| File | Responsibility |
|---|---|
| `app/scanner.py` | Owns rules, archive limits and directory loading. |
| `app/cli.py` | Converts command-line arguments into a report and exit code. |
| `app/main.py` | Provides web/API adapters and input-size limits. |
| `static/app.js` | Uploads a ZIP, filters findings and exports JSON. |
| `tests/test_scanner.py` | Exercises redaction, traversal, decompression limits and API behavior. |

## Why these technologies

Python provides file handling, regular expressions and ZIP support in the standard library. A pure function separates the rule engine from interfaces. FastAPI adds an automatically documented API without changing the scanner behavior.

## Trace one action

1. Choose a source ZIP or call the CLI on a directory.
2. The input adapter validates size, paths and formats; it does not execute source.
3. The scanner checks project-level essentials and then applies text rules.
4. Each match becomes a finding with rule ID, severity, path and line.
5. Reports omit matched values and source snippets.
6. The interface sorts by severity, allows filtering and exports JSON.
7. A person reviews the finding in context because heuristics can be wrong.

## Ten likely interview questions

### 1. What is the scanner architecture?

A pure scan function accepts a filename-to-text mapping and returns structured findings. The CLI and API adapt their input into that format and reuse the same rules.

### 2. Does it run the code being scanned?

No. It reads text and matches deterministic patterns. The ZIP path does not extract archives, and the app never imports or executes uploaded source.

### 3. What is a false positive?

A finding on safe code, such as a synthetic test password or harmless example of eval. The report asks for human review instead of claiming every match is exploitable.

### 4. Why omit source snippets?

A suspected credential should not be copied into another report. The report gives a path, line and rule but omits the matched value. Filenames can still reveal information.

### 5. What is a ZIP bomb?

An archive that expands dramatically and consumes memory or processing time. The input adapter checks compressed size, declared inflated sizes, ratios and counts before reading selected entries.

### 6. Why validate paths if you never extract?

It keeps the input contract safe and predictable, rejects traversal-like names, and prevents future code changes from accidentally trusting dangerous paths.

### 7. How can this work in CI?

The CLI exits with 1 when a finding meets the chosen severity threshold, which a CI job can treat as failure. JSON output is machine-readable for later processing.

### 8. Why are regular expressions limited?

They do not understand syntax, control flow or whether a value is trusted. A production tool could use language parsers and data-flow analysis, but would still need review.

### 9. What is the running time?

For a fixed set of simple rules, work grows roughly with the total text size. The current implementation rescans line prefixes to calculate locations and caps findings at 1,000; large-scale scanning would precompute offsets.

### 10. What does a clean report mean?

Only that these rules found no matches in the inspected files. It says nothing about all vulnerabilities, dependencies, deployment settings or files that were skipped.

## A practical exercise

Add a missing SECURITY.md rule and one positive and one negative fixture. Make sure its report cannot reveal source contents. Explain whether this is a security vulnerability or only a hygiene suggestion.

## Honest scope

Read the limits in the README. The implementation and its tests are real; external deployment, production operation, independent mastery and employer experience are not implied.
