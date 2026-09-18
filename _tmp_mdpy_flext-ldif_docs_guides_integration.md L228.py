# from flext-ldif/docs/guides/integration.md:228
from __future__ import annotations

from flext_api import FlextAPIService
from flext_ldif import ldif


class LdifAPIService(FlextAPIService):
    """REST API service for LDIF processing operations."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = ldif()

    def parse_ldif_endpoint(self, file_content: str) -> p.Result[m.Dict]:
        """API endpoint for LDIF parsing with memory awareness."""
        # Check content size before processing
        content_size = len(file_content.encode("utf-8"))
        max_size = 50 * 1024 * 1024  # 50MB for API operations

        if content_size > max_size:
            return r[m.Dict].fail({
                "status": "error",
                "message": f"LDIF content too large ({content_size} bytes). Maximum: {max_size} bytes.",
                "error_type": "memory_limit_exceeded",
            })

        return (
            self._ldif_api
            .parse_string(file_content)
            .map(
                lambda entries: {
                    "status": "success",
                    "entry_count": len(entries),
                    "memory_usage": f"{content_size} bytes processed",
                    "entries": [
                        self._serialize_ldif_entry(entry) for entry in entries[:100]
                    ],  # Limit response size
                }
            )
            .map_error(
                lambda error: {
                    "status": "error",
                    "message": f"LDIF parsing failed: {error}",
                    "error_type": "ldif_parse_error",
                }
            )
        )

    def _serialize_ldif_entry(self, entry) -> t.JsonMapping:
        """Serialize LDIF entry for API response."""
        return {
            "dn": entry.dn,
            "object_classes": entry.get_object_classes(),
            "is_person": entry.is_person(),
            "is_group": entry.is_group(),
            "attribute_count": len(entry.attributes),
        }```
### LDIF CLI Service Integration

