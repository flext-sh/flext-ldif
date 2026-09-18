# from flext-ldif_docs/troubleshooting.md:81
from __future__ import annotations

from flext_ldif import ldif, p, r
import pathlib


def handle_encoding_issues(file_path: str) -> p.Result[str]:
    """Handle various character encodings."""
    encodings_to_try = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

    for encoding in encodings_to_try:
        try:
            content = pathlib.Path(file_path).read_text(encoding=encoding)
            u.Cli.print(f"✓ Successfully read with {encoding} encoding")
            return r[str].ok(content)
        except UnicodeDecodeError:
            u.Cli.print(f"✗ Failed with {encoding} encoding")
            continue

    return r[str].fail("Unable to decode file with any supported encoding")


# Usage with custom encoding
def parse_with_encoding_detection(file_path: str) -> p.Result[list]:
    """Parse LDIF with automatic encoding detection."""
    content_result = handle_encoding_issues(file_path)
    if content_result.failure:
        return r[list].fail(content_result.error)

    api = ldif()
    return api.parse_string(content_result.unwrap())```
### Memory Issues

#### Out of Memory Errors

**Symptom**: Application crashes or becomes unresponsive with large LDIF files.

