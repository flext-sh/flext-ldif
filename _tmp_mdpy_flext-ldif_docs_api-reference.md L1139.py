# from flext-ldif/docs/api-reference.md:1139
from __future__ import annotations

from flext_ldif import u

# Structured logging in LDIF operations
logger = u.fetch_logger(__name__)

# Log processing operations
logger.info(
    "Starting LDIF processing",
    extra={"file_path": str(input_file), "settings": settings.model_dump()},
)

# Log processing results
logger.info(
    "LDIF processing completed",
    extra={"entries_processed": len(entries), "processing_time": elapsed_time},
)```
## 🚀 Quick Start Guide

### Basic Usage - Parse, Validate, Write

