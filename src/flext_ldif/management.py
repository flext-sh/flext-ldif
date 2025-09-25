"""FLEXT LDIF Management Layer.

Unified orchestration of schema, ACL, entry, and quirks management for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from pydantic import ConfigDict

from flext_core import FlextContainer, FlextLogger, FlextResult, FlextService
from flext_ldif.acls_coordinator import FlextLdifAcls
from flext_ldif.entries_coordinator import FlextLdifEntries
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser import FlextLdifParser

# from flext_ldif.processor import FlextLdifProcessor  # Avoid circular import
from flext_ldif.quirks_coordinator import FlextLdifQuirks
from flext_ldif.schemas_coordinator import FlextLdifSchemas


class FlextLdifManagement(FlextService[dict[str, object]]):
    """Master coordinator for schema, ACL, entry, and quirks operations using flext-core paradigm."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=False,
        extra="allow",
    )

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize management coordinator.

        Args:
            server_type: Target LDAP server type

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._server_type = server_type
        self._container = FlextContainer.get_global()

        # Initialize domain coordinators directly
        self.schemas: FlextLdifSchemas = FlextLdifSchemas()
        self.entries: FlextLdifEntries = FlextLdifEntries()
        self.acls: FlextLdifAcls = FlextLdifAcls()
        self.quirks: FlextLdifQuirks = FlextLdifQuirks()

        # Initialize nested coordinator classes
        self.schemas.extractor = self.schemas.Extractor(self.schemas)
        self.schemas.validator = self.schemas.Validator(self.schemas)
        self.acls.service = self.acls.Service(self.acls)
        self.quirks.manager = self.quirks.Manager(self.quirks)
        self.quirks.adapter = self.quirks.EntryAdapter(self.quirks)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": "FlextLdifManagement",
            "server_type": self._server_type,
            "coordinators": ["schemas", "entries", "acls", "quirks"],
        })

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": "FlextLdifManagement",
            "server_type": self._server_type,
            "coordinators": ["schemas", "entries", "acls", "quirks"],
        })

    def process_ldif_complete(
        self, content: str, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Complete LDIF processing pipeline.

        Args:
            content: LDIF content string
            server_type: Target server type (auto-detected if not provided)

        Returns:
            FlextResult with processed entries, schema, ACLs, and server type

        """
        # Parse content first using parser directly to avoid circular import
        parser = FlextLdifParser()
        parse_result: FlextResult[
            list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
        ] = parser.parse_string(content)

        if parse_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                parse_result.error or "Parse failed"
            )

        parsed_items = parse_result.value

        # Filter to only Entry types for processing
        entries: list[FlextLdifModels.Entry] = [
            item for item in parsed_items if isinstance(item, FlextLdifModels.Entry)
        ]

        # Detect server type if not provided
        if not server_type:
            server_result: FlextResult[str] = self.quirks.manager.detect_server_type(
                entries
            )
            server_type = server_result.value if server_result.is_success else "generic"

        # Extract and validate schemas
        schema_result: FlextResult[FlextLdifModels.SchemaDiscoveryResult] = (
            self.schemas.extractor.extract_from_entries(entries)
        )

        # Process ACLs
        acl_result: FlextResult[list[FlextLdifModels.UnifiedAcl]] = (
            self.acls.service.extract_from_entries(entries, server_type)
        )

        # Adapt for server quirks
        adapted_result: FlextResult[list[FlextLdifModels.Entry]] = (
            self.quirks.adapter.adapt_entries(entries, server_type)
        )

        return FlextResult[dict[str, object]].ok({
            "entries": adapted_result.value if adapted_result.is_success else entries,
            "schema": schema_result.value if schema_result.is_success else None,
            "acls": acl_result.value if acl_result.is_success else [],
            "server_type": server_type,
        })

    def process_entries_with_acl(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Process entries and extract ACLs using coordinators."""
        if not entries:
            return FlextResult[dict[str, object]].fail("No entries to process")

        server_type_result: FlextResult[str] = self.quirks.manager.detect_server_type(
            entries
        )
        if server_type_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                server_type_result.error or "Failed to detect server type"
            )

        server_type = server_type_result.value
        acl_result: FlextResult[list[FlextLdifModels.UnifiedAcl]] = (
            self.acls.service.extract_from_entries(entries, server_type)
        )

        return FlextResult[dict[str, object]].ok({
            "server_type": server_type,
            "entry_count": len(entries),
            "acl_count": len(acl_result.value) if acl_result.is_success else 0,
            "acls": acl_result.value if acl_result.is_success else [],
        })

    def process_entries_with_schema(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Process entries and extract schema using coordinators."""
        if not entries:
            return FlextResult[dict[str, object]].fail("No entries to process")

        schema_result: FlextResult[FlextLdifModels.SchemaDiscoveryResult] = (
            self.schemas.extractor.extract_from_entries(entries)
        )
        if schema_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                schema_result.error or "Failed to extract schema"
            )

        schema = schema_result.value

        validation_results: list[dict[str, object]] = []
        for entry in entries:
            val_result: FlextResult[dict[str, object]] = (
                self.schemas.validator.validate_entry(entry, schema)
            )
            if val_result.is_success:
                validation_results.append(val_result.value)

        return FlextResult[dict[str, object]].ok({
            "schema": schema,
            "entry_count": len(entries),
            "validation_results": validation_results,
        })

    def adapt_entries_for_server(
        self, entries: list[FlextLdifModels.Entry], target_server: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Adapt entries for target server type using coordinators."""
        return self.quirks.adapter.adapt_entries(entries, target_server)

    def validate_entries_for_server(
        self, entries: list[FlextLdifModels.Entry], server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Validate entries for server compliance using coordinators."""
        target_server = server_type or self._server_type or "generic"
        return self.quirks.adapter.validate_entries_for_server(entries, target_server)


__all__ = ["FlextLdifManagement"]
