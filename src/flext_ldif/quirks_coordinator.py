"""FLEXT LDIF Quirks Coordinator.

Unified quirks management coordinator using flext-core paradigm with nested
operation classes.
"""

from __future__ import annotations

from typing import override

from pydantic import ConfigDict

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import (
    FlextLdifEntryQuirks,
    FlextLdifQuirksManager,
)


class FlextLdifQuirks(FlextService[dict[str, object]]):
    """Unified quirks management coordinator following flext-core single class paradigm.

    Provides comprehensive quirks management operations including detection,
    adaptation, and handling of LDAP server-specific behaviors and anomalies.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=False,
        extra="allow",
    )

    class Manager:
        """Nested class for quirks management operations."""

        @override
        def __init__(self, parent: FlextLdifQuirks) -> None:
            """Initialize quirks manager with parent coordinator reference."""
            self._parent = parent
            self._manager = FlextLdifQuirksManager()
            self._logger = FlextLogger(__name__)

        def detect_server_type(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[str]:
            """Detect LDAP server type from entries."""
            return self._manager.detect_server_type(entries)

        def get_server_quirks(
            self, server_type: str | None = None
        ) -> FlextResult[dict[str, object]]:
            """Get quirks configuration for server type."""
            return self._manager.get_server_quirks(server_type)

        def get_acl_attribute_name(
            self, server_type: str | None = None
        ) -> FlextResult[str]:
            """Get ACL attribute name for server type."""
            return self._manager.get_acl_attribute_name(server_type)

        def get_acl_format(self, server_type: str | None = None) -> FlextResult[str]:
            """Get ACL format for server type."""
            return self._manager.get_acl_format(server_type)

    class EntryAdapter:
        """Nested class for entry adaptation operations."""

        @override
        def __init__(self, parent: FlextLdifQuirks) -> None:
            """Initialize entry adapter with parent coordinator reference."""
            self._parent = parent
            self._adapter = FlextLdifEntryQuirks()
            self._logger = FlextLogger(__name__)

        def adapt_entry(
            self, entry: FlextLdifModels.Entry, server_type: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Adapt entry for specific server type."""
            return self._adapter.adapt_entry(entry, server_type)

        def adapt_entries(
            self, entries: list[FlextLdifModels.Entry], server_type: str
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Adapt multiple entries for server type."""
            adapted_entries: list[FlextLdifModels.Entry] = []

            for entry in entries:
                adapt_result: FlextResult[FlextLdifModels.Entry] = (
                    self._adapter.adapt_entry(entry, server_type)
                )
                if adapt_result.is_success:
                    adapted_entries.append(adapt_result.value)
                else:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to adapt entry {entry.dn}: {adapt_result.error}"
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

        def validate_for_server(
            self, entry: FlextLdifModels.Entry, server_type: str
        ) -> FlextResult[bool]:
            """Validate entry compatibility with server type."""
            result = self._adapter.validate_entry(entry, server_type)
            if result.is_success:
                compliant_value = result.value.get("compliant", False)
                # Ensure compliant is a boolean
                compliant = (
                    bool(compliant_value) if compliant_value is not None else False
                )
                return FlextResult[bool].ok(compliant)
            return FlextResult[bool].fail(result.error or "Validation failed")

        def validate_entries_for_server(
            self, entries: list[FlextLdifModels.Entry], server_type: str
        ) -> FlextResult[dict[str, object]]:
            """Validate multiple entries for server compatibility."""
            validation_results: dict[str, object] = {
                "valid_count": 0,
                "invalid_count": 0,
                "errors": [],
            }

            for entry in entries:
                validate_result = self._adapter.validate_entry(entry, server_type)
                if validate_result.is_success:
                    compliant_value = validate_result.value.get("compliant", False)
                    compliant = (
                        bool(compliant_value) if compliant_value is not None else False
                    )
                    if compliant:
                        current_valid = validation_results["valid_count"]
                        validation_results["valid_count"] = int(str(current_valid)) + 1
                    else:
                        current_invalid = validation_results["invalid_count"]
                        validation_results["invalid_count"] = (
                            int(str(current_invalid)) + 1
                        )
                        errors_list = validation_results["errors"]
                        if isinstance(errors_list, list):
                            errors_list.append({
                                "dn": entry.dn.value,
                                "error": "Server compliance validation failed",
                            })
                else:
                    current_invalid = validation_results["invalid_count"]
                    validation_results["invalid_count"] = int(str(current_invalid)) + 1
                    errors_list = validation_results["errors"]
                    if isinstance(errors_list, list):
                        errors_list.append({
                            "dn": entry.dn.value,
                            "error": validate_result.error or "Validation failed",
                        })

            return FlextResult[dict[str, object]].ok(validation_results)

    @override
    def __init__(self) -> None:
        """Initialize quirks coordinator with nested operation classes."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        self.manager = self.Manager(self)
        self.adapter = self.EntryAdapter(self)

    @override
    def execute(self: object) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": FlextLdifQuirks,
            "operations": ["manager", "adapter"],
        })

    async def execute_async(self: object) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": FlextLdifQuirks,
            "operations": ["manager", "adapter"],
        })


__all__ = ["FlextLdifQuirks"]
