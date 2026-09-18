# from flext-ldif_docs/troubleshooting.md:44
from __future__ import annotations


def diagnose_ldif_format(content: str) -> None:
    """Diagnose LDIF format issues."""
    lines = content.strip().split("\n")

    u.Cli.print(f"Total lines: {len(lines)}")
    u.Cli.print("First few lines:")
    for i, line in enumerate(lines[:5]):
        u.Cli.print(f"{i + 1}: '{line}'")

    # Check for common issues
    if not any(line.startswith("dn:") for line in lines):
        u.Cli.print("❌ No DN found - LDIF entries must start with 'dn:'")

    # Check line folding issues
    for i, line in enumerate(lines):
        if line.startswith(" ") and i == 0:
            u.Cli.print(f"❌ Line {i + 1} starts with space but is first line")

    # Check character encoding
    try:
        content.encode("utf-8")
        u.Cli.print("✓ UTF-8 encoding valid")
    except UnicodeError as e:
        u.Cli.print(f"❌ Encoding issue: {e}")```
#### Character Encoding Issues

**Symptom**: Parse fails with encoding-related errors.

