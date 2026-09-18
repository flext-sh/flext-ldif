# from flext-ldif_docs/configuration.md:449
from __future__ import annotations

# Configuration changelog
CONFIGURATION_CHANGELOG = {
    "0.9.9": {
        "added": ["buffer_size", "log_level"],
        "changed": ["max_entries default from 10000 to None"],
        "deprecated": [],
    }
}


def get_config_version() -> str:
    """Get current configuration version."""
    return "0.9.9"```
## Configuration Reference

### Complete Configuration Options

| Option                      | Type   | Default   | Description                                 |                                               |
| --------------------------- | ------ | --------- | ------------------------------------------- | --------------------------------------------- |
| `max_entries`               | `int \ | None`     | `None`                                      | Maximum entries to process (None = unlimited) |
| `strict_validation`         | `bool` | `False`   | Enable strict RFC 2849 validation           |                                               |
| `ignore_unknown_attributes` | `bool` | `True`    | Ignore non-standard attributes              |                                               |
| `encoding`                  | `str`  | `"utf-8"` | Character encoding for files                |                                               |
| `line_separator`            | `str`  | `"\\n"`   | Line separator for output                   |                                               |
| `buffer_size`               | `int`  | `8192`    | File operation buffer size                  |                                               |
| `log_level`                 | `str`  | `"INFO"`  | Logging level (DEBUG, INFO, WARNING, ERROR) |                                               |

### Environment Variable Mapping

| Environment Variable              | Configuration Option        | Example  |
| --------------------------------- | --------------------------- | -------- |
| `FLEXT_LDIF_MAX_ENTRIES`          | `max_entries`               | `100000` |
| `FLEXT_LDIF_STRICT_VALIDATION`    | `strict_validation`         | `true`   |
| `FLEXT_LDIF_IGNORE_UNKNOWN_ATTRS` | `ignore_unknown_attributes` | `false`  |
| `FLEXT_LDIF_ENCODING`             | `encoding`                  | `utf-8`  |
| `FLEXT_LDIF_BUFFER_SIZE`          | `buffer_size`               | `16384`  |
| `FLEXT_LDIF_LOG_LEVEL`            | `log_level`                 | `DEBUG`  |

______________________________________________________________________

This configuration guide provides comprehensive coverage of FLEXT-LDIF configuration options while maintaining integration with FLEXT ecosystem patterns and professional configuration management practices.
