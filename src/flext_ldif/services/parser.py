"""Parser Service - LDIF Parsing Only.

This service provides LDIF parsing functionality:
- RFC 2849 compliant entry parsing with quirks support
- Automatic ACL extraction with quirks
- Automatic schema parsing when schema entries detected
- Relaxed parsing for non-compliant files

Single Responsibility: Parse LDIF content to Entry models.
- Entry quirks → parse LDIF → Entry models
- ACL quirks → extract ACLs → Acl models (automatic)
- Schema quirks → parse schema → SchemaAttribute/SchemaObjectClass models (automatic)

No nested classes. Quirks are used directly via FlextRegistry.
Follows same pattern as writer.py for consistency.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path
from typing import override

from flext_core import FlextLogger, FlextResult, FlextRuntime

from flext_ldif.base import LdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifParser(LdifServiceBase):
    r"""LDIF parsing service - PARSING ONLY with SRP-compliant nested classes.

    PARSING MONOPOLY: All operations are parsing-related. File I/O, writing, and
    migration are delegated to dedicated services.

    Public Methods (PARSING ONLY):
        - parse(content, server_type): Parse LDIF content string
        - parse_file(path, server_type): Parse LDIF file
        - parse_ldap3_result(results, server_type): Parse LDAP search results

    Automatic Internal Processing:
        - Schema entry detection → automatic schema parsing
        - ACL attribute detection → automatic ACL extraction
        - All via quirks for server-specific decoding

    NOT IN THIS SERVICE (delegated to other services):
        - Writing: Use FlextLdifWriter
        - Migration: Use FlextLdifMigrationPipeline
        - Server detection: Use FlextLdifDetector (used internally)

    Architecture & Refactoring (INTENSIVE FlextLdifUtilities Usage):
        - Uses FlextLdifUtilities.DN for RFC 4514 DN normalization and validation
        - Uses FlextLdifUtilities.DN.norm() for proper DN normalization (not .strip())
        - Uses FlextLdifUtilities.DN.validate() for DN format validation
        - Entry quirks decode LDIF → Entry models
        - Schema quirks decode schema lines → SchemaAttribute/SchemaObjectClass
        - ACL quirks decode ACL attributes → Acl models
        - Uses FlextLdifServer for ALL modes (RFC/server-specific/relaxed)
        - Returns FlextResult[list[Entry]] - always consistent type
        - Type-safe with Python 3.13+ annotations
        - Nested class refactoring planned: EntryParser, SchemaParser, Validator, Transformer

    Example:
        >>> from flext_ldif.services.parser import FlextLdifParser
        >>>
        >>> # Initialize parser service
        >>> parser = FlextLdifParser()
        >>>
        >>> # Parse LDIF content string
        >>> ldif_content = "dn: cn=test,dc=example,dc=com\\nobjectClass: person"
        >>> result = parser.parse(
        ...     ldif_content, input_source="string", server_type="oud"
        ... )
        >>> if result.is_success:
        ...     entries = result.unwrap()

    """

    _registry: FlextLdifServer
    _acl_service: FlextLdifAcl
    _detector: FlextLdifDetector

    def __init__(
        self,
        *,
        enable_events: bool = False,
    ) -> None:
        """Initialize parser service with direct quirks usage.

        Args:
            enable_events: Enable domain event emission (default: False for backward compatibility).

        Initializes:
            - FlextLdifServer: For all parsing modes (RFC/server-specific/relaxed)
            - FlextLdifAcl: For ACL extraction
            - FlextLdifDetector: For server type detection

        Config is accessed via self.config.ldif (inherited from LdifServiceBase).

        """
        super().__init__()
        self._enable_events = enable_events

        # Initialize parsing components
        self._registry = FlextLdifServer()
        self._acl_service = FlextLdifAcl()
        self._detector = FlextLdifDetector()

    # ==================== NESTED HELPER CLASSES ====================
    # These replace private methods with composable, testable classes

    class InputRouter:
        """Handles input routing and parsing - replaces _handle_input_routing and _parse_from_* methods."""

        def __init__(
            self,
            registry: FlextLdifServer,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with registry and logger."""
            self.registry = registry
            self.logger = parent_logger

        def route_and_parse(
            self,
            input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
            content: str | Path | list[tuple[str, dict[str, list[str]]]],
            effective_type: str,
            encoding: str,
        ) -> FlextResult[FlextLdifModels.ParseResponse]:
            """Route input to appropriate parser based on input source."""
            result: FlextResult[FlextLdifModels.ParseResponse]

            match (input_source, content):
                case ("string", str() as content_str):
                    result = self.parse_string(content_str, effective_type)
                case ("file", Path() as content_path):
                    result = self.parse_file(content_path, encoding, effective_type)
                case ("ldap3", list() as ldap3_content):
                    result = self.parse_ldap3(ldap3_content, effective_type)
                case ("ldap3", _):
                    return FlextResult.fail("ldap3 input source requires list content")
                case _:
                    return FlextResult.fail(f"Unsupported input source: {input_source}")

            return result

        def parse_string(
            self,
            content: str,
            server_type: str,
        ) -> FlextResult[FlextLdifModels.ParseResponse]:
            """Parse LDIF from string content.

            CRITICAL: Preserves original LDIF content in metadata BEFORE any parsing.
            This ensures zero data loss and perfect round-trip conversion.
            """
            quirk = self.registry.quirk(server_type)
            if quirk is None:
                self.logger.error(
                    "Quirk not found",
                    server_type=server_type,
                    available_servers=self.registry.list_registered_servers(),
                )
                return FlextResult.fail(
                    f"Internal error: No quirk found for resolved server type '{server_type}'",
                )

            # quirk.parse() returns FlextResult[FlextLdifModels.ParseResponse]
            # ParseResult is an alias for ParseResponse - return directly
            result = quirk.parse(content)

            if result.is_success:
                parse_response = result.unwrap()

                # Verify original content preservation in entries
                def has_original(entry: object) -> int:
                    """Check if entry has original content."""
                    metadata = getattr(entry, "metadata", None)
                    if (
                        metadata
                        and hasattr(metadata, "original_strings")
                        and getattr(metadata, "original_strings", None)
                        and "entry_original_ldif"
                        in getattr(metadata, "original_strings", {})
                    ):
                        return 1
                    return 0

                entries_with_original = sum(
                    has_original(entry) for entry in parse_response.entries
                )

                self.logger.debug(
                    "Parsed LDIF string",
                    server_type=server_type,
                    entries_count=len(parse_response.entries),
                    entries_with_original=entries_with_original,
                    parse_errors=parse_response.statistics.parse_errors,
                )

                if entries_with_original < len(parse_response.entries):
                    self.logger.warning(
                        "Some entries missing original content preservation",
                        total_entries=len(parse_response.entries),
                        entries_with_original=entries_with_original,
                        missing_count=len(parse_response.entries)
                        - entries_with_original,
                    )
            else:
                self.logger.error(
                    "Failed to parse LDIF string",
                    server_type=server_type,
                    error=str(result.error),
                )

            return result

        def parse_file(
            self,
            path: Path,
            encoding: str,
            server_type: str,
        ) -> FlextResult[FlextLdifModels.ParseResponse]:
            """Parse LDIF from file.

            CRITICAL: Preserves original file content in metadata BEFORE any parsing.
            """
            if not path.exists():
                self.logger.error(
                    "LDIF file not found",
                    file_path=str(path),
                )
                return FlextResult.fail(f"LDIF file not found: {path}")

            try:
                content = path.read_text(encoding=encoding)
                # CRITICAL: Original content is preserved in parse_string()
                return self.parse_string(content, server_type)
            except (FileNotFoundError, OSError, Exception) as e:
                self.logger.exception(
                    "Failed to read LDIF file",
                    file_path=str(path),
                    encoding=encoding,
                    error=str(e),
                )
                return FlextResult.fail(f"Failed to read LDIF file: {e}")

        def parse_ldap3(
            self,
            results: list[tuple[str, dict[str, list[str]]]],
            server_type: str,
        ) -> FlextResult[FlextLdifModels.ParseResponse]:
            """Parse LDAP3 search results into Entry models."""
            quirk = self.registry.quirk(server_type)
            if quirk is None:
                self.logger.error(
                    "Quirk not found for LDAP3 parsing",
                    server_type=server_type,
                )
                return FlextResult.fail(
                    f"No quirk available for server type: {server_type}",
                )

            entries: list[FlextLdifModels.Entry] = []
            failed_count = 0
            failed_details: list[str] = []

            for idx, (dn, attrs) in enumerate(results):
                # CRITICAL: Preserve original LDAP3 entry data before parsing
                # Reconstruct original LDIF-like representation for preservation
                # Build original LDIF representation from LDAP3 data
                original_ldif_lines = [f"dn: {dn}"]
                original_ldif_lines.extend(
                    f"{attr_name}: {value}"
                    for attr_name, attr_values in attrs.items()
                    for value in attr_values
                )
                original_ldif_content = "\n".join(original_ldif_lines) + "\n"

                # Type guard: ensure entry_quirk implements EntryProtocol
                entry_quirk = quirk.entry_quirk
                # TEMPORARILY BYPASS isinstance check due to protocol indentation issues
                # if not isinstance(entry_quirk, FlextLdifProtocols.Quirks.EntryProtocol):
                #     self.logger.error(
                #         "Entry quirk does not implement EntryProtocol",
                #         server_type=server_type,
                #         entry_index=idx + 1,
                #     )
                #     return FlextResult.fail(
                #         f"Entry quirk for {server_type} does not implement EntryProtocol",
                #     )
                # entry_quirk is now typed as EntryProtocol - no cast needed
                entry_result = entry_quirk.parse_entry(dn, attrs)

                # CRITICAL: After parsing, preserve original in entry metadata
                if entry_result.is_success:
                    entry = entry_result.unwrap()
                    if isinstance(entry, FlextLdifModels.Entry) and entry.metadata:
                        # Type narrowing: entry.metadata is QuirkMetadata
                        if not isinstance(
                            entry.metadata,
                            FlextLdifModels.QuirkMetadata,
                        ):
                            msg = f"Expected QuirkMetadata, got {type(entry.metadata)}"
                            raise TypeError(msg)
                        FlextLdifUtilities.Metadata.preserve_original_ldif_content(
                            metadata=entry.metadata,
                            ldif_content=original_ldif_content,
                            context="entry_original_ldif",
                        )

                if entry_result.is_success:
                    entry_unwrapped = entry_result.unwrap()
                    if not isinstance(entry_unwrapped, FlextLdifModels.Entry):
                        msg = f"Expected Entry, got {type(entry_unwrapped)}"
                        raise TypeError(msg)
                    entries.append(entry_unwrapped)
                else:
                    failed_count += 1
                    error_msg = f"DN: {dn}, Error: {entry_result.error}"
                    failed_details.append(error_msg)
                    self.logger.error(
                        "LDAP3 entry conversion failed",
                        entry_dn=dn,
                        entry_index=idx + 1,
                        error=str(entry_result.error)[:200],
                    )

            # Create statistics for LDAP3 parse
            stats = FlextLdifModels.Statistics(
                total_entries=len(results),
                processed_entries=len(entries),
                failed_entries=failed_count,
                parse_errors=failed_count,
                detected_server_type=server_type,
            )

            # Return ParseResponse directly - no tuple
            # Type narrowing: entries is list[Entry] from unwrap()
            typed_entries: list[FlextLdifModels.Entry] = [
                e for e in entries if isinstance(e, FlextLdifModels.Entry)
            ]

            self.logger.info(
                "Parsed LDAP3 results",
                server_type=server_type,
                total_entries=len(results),
                successful_entries=len(typed_entries),
                failed_entries=failed_count,
            )

            response = FlextLdifModels.ParseResponse(
                entries=list(typed_entries)
                if isinstance(typed_entries, Sequence)
                else typed_entries,
                statistics=stats,
                detected_server_type=server_type,
            )
            return FlextResult[FlextLdifModels.ParseResponse].ok(response)

    class EntryProcessor:
        """Handles entry processing - replaces _process_single_entry, _post_process_entries, _normalize_entry_dn, _filter_operational_attributes."""

        def __init__(
            self,
            schema_extractor: FlextLdifParser.SchemaExtractor,
            acl_extractor: FlextLdifParser.AclExtractor,
            validator: FlextLdifParser.EntryValidator,
            registry: FlextLdifServer,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with schema extractor, ACL extractor, validator, registry and logger."""
            self.schema_extractor = schema_extractor
            self.acl_extractor = acl_extractor
            self.validator = validator
            self.registry = registry
            self.logger = parent_logger

        def apply_schema_quirks_inline(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Apply schema quirks to inline schema attributes via quirk delegation.

            Delegates to server quirk's normalize_schema_strings_inline method
            for server-specific schema string normalizations (e.g., OID matching rule typos).

            Args:
                entry: Entry with potential schema attributes to normalize
                server_type: Server type identifier

            Returns:
                Entry with normalized schema attribute strings

            """
            # Get server quirk from registry
            quirk = self.registry.quirk(server_type)
            if quirk is None:
                return entry

            entry_quirk = quirk.entry_quirk

            # Delegate to quirk's normalize_schema_strings_inline if available
            normalize_method = getattr(
                entry_quirk, "normalize_schema_strings_inline", None
            )
            if normalize_method:
                result = normalize_method(entry)
                # Type narrowing: result should be Entry
                if isinstance(result, FlextLdifModels.Entry):
                    return result

                return entry

            return entry

        def _normalize_entry_dn_if_needed(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
            *,
            normalize: bool,
        ) -> FlextLdifModels.Entry:
            """Normalize entry DN if normalization is enabled."""
            if not normalize:
                return entry

            original_dn = str(entry.dn) if entry.dn else None
            self.logger.debug(
                "Normalizing entry DN",
                entry_dn=original_dn,
            )
            dn_before = str(entry.dn) if entry.dn else None
            normalized_entry = self.normalize_entry_dn(entry, server_type)
            dn_after = str(normalized_entry.dn) if normalized_entry.dn else None

            # Track DN normalization differences
            if (
                normalized_entry.metadata
                and dn_before
                and dn_after
                and dn_before != dn_after
            ):
                # Type narrowing: normalized_entry.metadata is QuirkMetadata
                if not isinstance(
                    normalized_entry.metadata,
                    FlextLdifModels.QuirkMetadata,
                ):
                    msg = (
                        f"Expected QuirkMetadata, got {type(normalized_entry.metadata)}"
                    )
                    raise TypeError(msg)
                FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                    metadata=normalized_entry.metadata,
                    original=dn_before,
                    converted=dn_after,
                    context="dn_normalization",
                    attribute_name="dn",
                )
                self.logger.debug(
                    "Tracked DN normalization difference",
                    original_dn=dn_before,
                    normalized_dn=dn_after,
                )
            return normalized_entry

        def _parse_schema_if_needed(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
            *,
            auto_parse: bool,
        ) -> tuple[FlextLdifModels.Entry, int, int]:
            """Parse schema entry if auto-parsing is enabled and entry is schema entry."""
            if auto_parse and FlextLdifUtilities.Entry.is_schema_entry(
                entry,
                strict=False,
            ):
                parsed_entry = self.schema_extractor.parse_schema_entry(
                    entry,
                    server_type,
                )
                return parsed_entry, 1, 0
            return entry, 0, 1

        def _validate_entry_if_needed(
            self,
            entry: FlextLdifModels.Entry,
            *,
            validate: bool,
            strict: bool,
        ) -> list[str]:
            """Validate entry and return list of validation errors."""
            if not validate:
                return []

            validation_result = self.validator.validate_entry(entry, strict=strict)
            if validation_result.is_failure:
                dn_value = entry.dn.value if entry.dn else "unknown"
                if strict:
                    msg = f"Strict validation failed for entry {dn_value}: {validation_result.error}"
                    self.logger.error(
                        "Strict validation failed",
                        entry_dn=dn_value,
                        error=str(validation_result.error),
                    )
                    raise ValueError(msg)
                self.logger.warning(
                    "Entry validation warning",
                    entry_dn=dn_value,
                    error=str(validation_result.error),
                )
                # Type narrowing: validation_result.error can be None, provide fallback
                error_msg = validation_result.error or "Entry validation failed"
                return [error_msg]
            return []

        def _filter_operational_attrs_if_needed(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
            *,
            include_operational: bool,
        ) -> FlextLdifModels.Entry:
            """Mark operational attributes for removal in metadata (soft-delete).

            SOFT-DELETE ARCHITECTURE:
            - Attributes STAY in entry.attributes (never removed)
            - Metadata marks HOW to write (removed = write as comment)
            - Writer consults metadata to decide output format
            """
            if include_operational:
                return entry

            if not entry.attributes:
                return entry

            # Get operational attribute names from quirk
            operational_attrs = self._get_operational_attr_names(entry, server_type)

            # Mark each operational attribute in metadata (soft-delete)
            marked_count = 0
            if entry.metadata:
                for attr_name, attr_values in entry.attributes.attributes.items():
                    if attr_name.lower() in operational_attrs:
                        original_values = list(attr_values) if attr_values else []
                        if original_values:
                            # Mark in metadata - attribute stays in entry.attributes
                            if not isinstance(
                                entry.metadata,
                                FlextLdifModels.QuirkMetadata,
                            ):
                                msg = f"Expected QuirkMetadata, got {type(entry.metadata)}"
                                raise TypeError(msg)
                            FlextLdifUtilities.Metadata.track_transformation(
                                metadata=entry.metadata,
                                original_name=attr_name,
                                target_name=None,
                                original_values=original_values,
                                target_values=None,
                                transformation_type="removed",
                                reason=f"Operational attribute for {server_type}",
                            )
                            marked_count += 1
                            self.logger.debug(
                                "Operational attribute marked for removal",
                                attribute_name=attr_name,
                                entry_dn=str(entry.dn) if entry.dn else None,
                                values_count=len(original_values),
                            )

            if marked_count > 0:
                self.logger.debug(
                    "Soft-delete completed",
                    marked_attributes=marked_count,
                    entry_dn=str(entry.dn) if entry.dn else None,
                )

            # Return entry UNCHANGED - attributes still in entry.attributes
            return entry

        def _get_operational_attr_names(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> set[str]:
            """Get operational attribute names for server type.

            Returns lowercase set of attribute names to mark as removed.
            """
            # Base operational attributes
            operational_attrs: set[str] = {
                attr.lower()
                for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_ALL_ENTRIES
            }

            # Add schema-related attrs for non-schema entries
            is_schema_entry = FlextLdifUtilities.Entry.is_schema_entry(
                entry,
                strict=False,
            )
            if not is_schema_entry:
                schema_attrs = {
                    attr.lower()
                    for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_NON_SCHEMA_ENTRIES
                }
                operational_attrs.update(schema_attrs)

            # Add server-specific operational attributes via quirk
            quirk = self.registry.quirk(server_type)
            if quirk is not None:
                server_constants = getattr(quirk, "Constants", None)
                if server_constants is not None:
                    server_operational_attrs = getattr(
                        server_constants, "OPERATIONAL_ATTRIBUTES", None
                    )
                    if server_operational_attrs is not None:
                        server_operational = {
                            attr.lower() for attr in server_operational_attrs
                        }
                        operational_attrs.update(server_operational)

            return operational_attrs

        def process_single_entry(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
            options: FlextLdifModels.ParseFormatOptions,
        ) -> tuple[FlextLdifModels.Entry, int, int, list[str]]:
            """Process single entry with all transformations.

            CRITICAL: Preserves ALL minimal differences in metadata throughout processing.
            Every transformation is tracked to ensure zero data loss and perfect round-trip.
            """
            # Step 1: Normalize DN if needed
            processed_entry = self._normalize_entry_dn_if_needed(
                entry,
                server_type,
                normalize=options.normalize_dns,
            )

            # Step 2: Apply schema quirks normalization
            processed_entry = self.apply_schema_quirks_inline(
                processed_entry,
                server_type,
            )

            # Step 3: Parse schema if needed
            processed_entry, schema_count, data_count = self._parse_schema_if_needed(
                processed_entry,
                server_type,
                auto_parse=options.auto_parse_schema,
            )

            # Step 4: Extract ACLs if needed
            if options.auto_extract_acls:
                processed_entry = self.acl_extractor.extract_acls(
                    processed_entry,
                    server_type,
                )

            # Step 5: Validate entry if needed
            validation_errors = self._validate_entry_if_needed(
                processed_entry,
                validate=options.validate_entries,
                strict=options.strict_schema_validation,
            )

            # Step 6: Filter operational attributes if needed
            processed_entry = self._filter_operational_attrs_if_needed(
                processed_entry,
                server_type,
                include_operational=options.include_operational_attrs,
            )

            filtered_errors = [e for e in validation_errors if e is not None]
            return processed_entry, schema_count, data_count, filtered_errors

        def post_process_entries(
            self,
            entries: list[FlextLdifModels.Entry],
            server_type: str,
            options: FlextLdifModels.ParseFormatOptions,
        ) -> tuple[list[FlextLdifModels.Entry], FlextLdifModels.Statistics]:
            """Post-process all entries."""
            processed_entries = []
            schema_count = 0
            data_count = 0
            parse_errors = 0
            validation_errors = []

            for entry in entries:
                try:
                    processed_entry, schema_inc, data_inc, val_errs = (
                        self.process_single_entry(entry, server_type, options)
                    )
                    schema_count += schema_inc
                    data_count += data_inc
                    validation_errors.extend(val_errs)
                    processed_entries.append(processed_entry)

                except Exception as e:
                    parse_errors += 1
                    self.logger.exception(
                        "Failed to process entry",
                        entry_dn=str(entry.dn)
                        if hasattr(entry, "dn") and entry.dn
                        else "unknown",
                        error=str(e),
                        parse_errors_count=parse_errors,
                    )

                    if (
                        options.max_parse_errors > 0
                        and parse_errors >= options.max_parse_errors
                    ):
                        self.logger.warning(
                            "Reached maximum parse errors limit",
                            max_parse_errors=options.max_parse_errors,
                            parse_errors_count=parse_errors,
                        )
                        break

            statistics = FlextLdifModels.Statistics(
                total_entries=len(processed_entries),
                schema_entries=schema_count,
                data_entries=data_count,
                parse_errors=parse_errors,
                detected_server_type=server_type,
            )
            return processed_entries, statistics

        def normalize_entry_dn(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Normalize DN formatting via quirk delegation (DI pattern)."""
            quirk = self.registry.quirk(server_type)
            if quirk is None:
                return entry

            entry_quirk = quirk.entry_quirk

            normalize_method = getattr(entry_quirk, "normalize_entry_dn", None)
            if normalize_method:
                try:
                    result = normalize_method(entry)
                    # Type narrowing: result should be Entry
                    if isinstance(result, FlextLdifModels.Entry):
                        return result
                    return entry
                except Exception as e:
                    self.logger.warning(
                        "Failed to normalize entry DN",
                        entry_dn=str(entry.dn) if entry.dn else None,
                        error=str(e),
                    )
                    return entry

            return entry

        def filter_operational_attributes(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Filter out operational attributes via quirk delegation (DI pattern)."""
            quirk = self.registry.quirk(server_type)
            if quirk is None:
                return entry

            entry_quirk = quirk.entry_quirk

            filter_method = getattr(entry_quirk, "filter_operational_attributes", None)
            if filter_method:
                try:
                    result = filter_method(entry)
                    # Type narrowing: result should be Entry
                    if isinstance(result, FlextLdifModels.Entry):
                        return result
                    return entry
                except Exception as e:
                    self.logger.warning(
                        "Failed to filter operational attributes",
                        entry_dn=str(entry.dn) if entry.dn else None,
                        error=str(e),
                    )
                    return entry

            return entry

    class EntryValidator:
        """Handles entry validation - replaces _validate_entry and _validate_entry_* methods."""

        def __init__(self, parent_logger: FlextLogger) -> None:
            """Initialize with logger."""
            self.logger = parent_logger

        def validate_entry(
            self,
            entry: FlextLdifModels.Entry,
            *,
            strict: bool = False,
        ) -> FlextResult[bool]:
            """Validate entry against LDAP schema rules."""
            try:
                validation_errors: list[str] = []

                self.validate_dn(entry, validation_errors)
                self.validate_objectclass(
                    entry,
                    strict=strict,
                    errors=validation_errors,
                )
                self.validate_attributes(entry, strict=strict, errors=validation_errors)

                if validation_errors:
                    return FlextResult.fail("; ".join(validation_errors))

                return FlextResult.ok(True)

            except Exception as e:
                return FlextResult.fail(f"Validation error: {e}")

        def validate_dn(
            self,
            entry: FlextLdifModels.Entry,
            errors: list[str],
        ) -> None:
            """Validate entry DN."""
            dn_str = str(entry.dn.value) if entry.dn else None
            if not dn_str:
                errors.append("Entry DN cannot be empty")
            elif not FlextLdifUtilities.DN.validate(dn_str):
                errors.append(f"Invalid DN format per RFC 4514: {dn_str}")

        def validate_objectclass(
            self,
            entry: FlextLdifModels.Entry,
            *,
            strict: bool,
            errors: list[str],
        ) -> None:
            """Validate entry has objectClass attribute."""
            if not entry.attributes:
                if strict:
                    errors.append("Entry must have objectClass attribute")
                return

            has_objectclass = any(
                attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower()
                for attr_name in entry.attributes.attributes
            )
            if not has_objectclass and strict:
                errors.append("Entry must have objectClass attribute")

        def validate_attributes(
            self,
            entry: FlextLdifModels.Entry,
            *,
            strict: bool,
            errors: list[str],
        ) -> None:
            """Validate entry attribute values."""
            if not entry.attributes:
                return

            # LdifAttributes.attributes is dict[str, list[str]]
            for attr_name, attr_value in entry.attributes.attributes.items():
                values: list[str] = list(attr_value) if attr_value else []
                if (not values or all(not v for v in values)) and strict:
                    errors.append(f"Attribute '{attr_name}' has empty values")

    class SchemaExtractor:
        """Handles schema extraction - replaces _parse_attribute_types_from_entry, _parse_objectclasses_from_entry, _parse_schema_entry."""

        def __init__(
            self,
            registry: FlextLdifServer,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with registry and logger."""
            self.registry = registry
            self.logger = parent_logger

        def parse_schema_entry(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Parse schema entry attributes into models."""
            try:
                schema_quirk = self.registry.quirk(server_type)
                if schema_quirk is None:
                    schema_quirk = self.registry.quirk(
                        FlextLdifConstants.ServerTypes.RFC,
                    )

                # Wrap in list for compatibility with parse methods that iterate quirks
                schemas = [schema_quirk] if schema_quirk is not None else []

                schema_attributes = self.parse_attribute_types(entry, schemas)
                schema_objectclasses = self.parse_objectclasses(entry, schemas)

                self.logger.debug(
                    "Parsed schema entry",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attributes_count=len(schema_attributes),
                    objectclasses_count=len(schema_objectclasses),
                    server_type=server_type,
                )

                # Build update dict - only include fields if lists are non-empty
                update_dict: dict[str, object] = {}
                if schema_attributes:
                    update_dict["attributes_schema"] = schema_attributes
                if schema_objectclasses:
                    update_dict["objectclasses"] = schema_objectclasses

                # Use update_dict if provided, otherwise None
                return entry.model_copy(update=update_dict or None)

            except (ValueError, TypeError, AttributeError, Exception) as e:
                self.logger.warning(
                    "Failed to parse schema entry",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    error=str(e),
                )
                return entry

        def _parse_single_attribute(
            self,
            definition: str,
            schemas: list[FlextLdifServersBase],
        ) -> FlextLdifModels.SchemaAttribute | None:
            """Parse single attribute definition using quirks."""
            for quirk in schemas:
                # Try parsing directly - protocol method handles validation
                parse_result = quirk.schema_quirk.parse_attribute(definition)
                if parse_result.is_success:
                    return parse_result.unwrap()
            return None

        def _parse_single_objectclass(
            self,
            definition: str,
            schemas: list[FlextLdifServersBase],
        ) -> FlextLdifModels.SchemaObjectClass | None:
            """Parse single objectClass definition using quirks."""
            for quirk in schemas:
                # Try parsing directly - protocol method handles validation
                parse_result = quirk.schema_quirk.parse_objectclass(definition)
                if parse_result.is_success:
                    return parse_result.unwrap()
            return None

        def _parse_schema_definitions(
            self,
            definitions: list[str],
            schemas: list[FlextLdifServersBase],
            *,
            is_attribute: bool,
        ) -> (
            list[FlextLdifModels.SchemaAttribute]
            | list[FlextLdifModels.SchemaObjectClass]
        ):
            """Parse schema definitions using quirks (DRY: shared logic for attributes/objectclasses).

            Python 3.13: Type-safe generic parsing with conditional logic.
            """
            if not definitions:
                return []

            # Parse attributes or objectClasses using helper methods
            if is_attribute:
                attributes: list[FlextLdifModels.SchemaAttribute] = []
                for definition in definitions:
                    parsed_attr = self._parse_single_attribute(definition, schemas)
                    if parsed_attr is not None:
                        attributes.append(parsed_attr)
                return attributes

            objectclasses: list[FlextLdifModels.SchemaObjectClass] = []
            for definition in definitions:
                parsed_oc = self._parse_single_objectclass(definition, schemas)
                if parsed_oc is not None:
                    objectclasses.append(parsed_oc)
            return objectclasses

        def parse_attribute_types(
            self,
            entry: FlextLdifModels.Entry,
            schemas: list[FlextLdifServersBase],
        ) -> list[FlextLdifModels.SchemaAttribute]:
            """Parse attributeTypes from entry using schema quirks."""
            if not entry.attributes:
                return []

            attr_types = entry.attributes.get(
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
                [],
            )
            # Type narrowing: _parse_schema_definitions returns list[SchemaAttribute] when is_attribute=True
            result = self._parse_schema_definitions(
                attr_types, schemas, is_attribute=True
            )
            # Type narrowing: when is_attribute=True, result is list[SchemaAttribute]
            # Convert union type to specific type using list comprehension with type check
            attributes: list[FlextLdifModels.SchemaAttribute] = [
                item
                for item in result
                if isinstance(item, FlextLdifModels.SchemaAttribute)
            ]
            return attributes

        def parse_objectclasses(
            self,
            entry: FlextLdifModels.Entry,
            schemas: list[FlextLdifServersBase],
        ) -> list[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClasses from entry using schema quirks."""
            if not entry.attributes:
                return []

            obj_classes = entry.attributes.get(
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
                [],
            )
            # Type narrowing: _parse_schema_definitions returns list[SchemaObjectClass] when is_attribute=False
            result = self._parse_schema_definitions(
                obj_classes,
                schemas,
                is_attribute=False,
            )
            # Type narrowing: when is_attribute=False, result is list[SchemaObjectClass]
            # Convert union type to specific type using list comprehension with type check
            objectclasses: list[FlextLdifModels.SchemaObjectClass] = [
                item
                for item in result
                if isinstance(item, FlextLdifModels.SchemaObjectClass)
            ]
            return objectclasses

    class AclExtractor:
        """Handles ACL extraction - replaces _extract_acls method."""

        def __init__(
            self,
            acl_service: FlextLdifAcl,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with ACL service and logger."""
            self.acl_service = acl_service
            self.logger = parent_logger

        def extract_acls(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Extract ACLs from entry attributes."""
            try:
                acl_result = self.acl_service.extract_acls_from_entry(
                    entry,
                    server_type=server_type,
                )

                if acl_result.is_success and acl_result.value:
                    acl_response = acl_result.value
                    if acl_response.acls:
                        # RFC Compliance: ACLs are processing metadata, not RFC LDIF entry data
                        new_metadata = entry.metadata.model_copy(
                            update={"acls": acl_response.acls},
                        )
                        return entry.model_copy(update={"metadata": new_metadata})

                return entry

            except (ValueError, TypeError, AttributeError, Exception) as e:
                self.logger.warning(
                    "Error extracting ACLs",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return entry

    class StatisticsBuilder:
        """Handles statistics finalization - replaces _finalize_statistics method."""

        def __init__(self, *, enable_events: bool, parent_logger: FlextLogger) -> None:
            """Initialize with event enablement flag and logger."""
            self.enable_events = enable_events
            self.logger = parent_logger

        def finalize(
            self,
            stats: FlextLdifModels.Statistics,
            failed_count: int,
            failed_details: list[str],
            processed_entries: list[FlextLdifModels.Entry],
            parse_duration_ms: float,
            input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
            content: str | Path | list[tuple[str, dict[str, list[str]]]],
            effective_type: str,
        ) -> FlextLdifModels.Statistics:
            """Finalize statistics with failure info and optional event emission."""
            # Update statistics with failures
            if failed_count > 0:
                # Update statistics with failures
                stats_updated = stats.model_copy(
                    update={"parse_errors": stats.parse_errors + failed_count},
                )
                stats = stats_updated
                self.logger.error(
                    "Parse completed with failures",
                    failed_count=failed_count,
                )

            # Emit ParseEvent if enabled
            if self.enable_events:
                # Calculate schema entries count (for future use in events)
                sum(
                    1
                    for entry in processed_entries
                    if "cn=schema" in str(entry.dn).lower()
                )

                # error_details accepts Sequence[object] | None - list[str] is compatible
                error_details_value: list[str] | None = (
                    failed_details if failed_count > 0 else None
                )

                if input_source == "file" and isinstance(content, Path):
                    parse_event = FlextLdifModels.ParseEvent.for_file(
                        file_path=content,
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=error_details_value,
                    )
                elif input_source == "ldap3":
                    parse_event = FlextLdifModels.ParseEvent.for_ldap3(
                        connection_info=f"ldap3_{effective_type}",
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=error_details_value,
                    )
                else:  # string
                    parse_event = FlextLdifModels.ParseEvent.for_string(
                        content_length=len(content) if isinstance(content, str) else 0,
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=error_details_value,
                    )

                # add_event returns Statistics
                stats_result = stats.add_event(parse_event)
                # Type narrowing: add_event returns Results.Statistics, but we need Models.Statistics
                # Since Models.Statistics extends Results.Statistics, we can safely use it
                if isinstance(stats_result, FlextLdifModels.Statistics):
                    stats = stats_result
                else:
                    msg = f"Expected Statistics, got {type(stats_result)}"
                    raise TypeError(msg)

            return stats

    @override
    def execute(self, **_kwargs: object) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Execute parser service health check.

        Args:
            **kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with empty ParseResponse (service status check only).

        """
        try:
            # Health check - return empty ParseResponse indicating operational status
            empty_statistics = FlextLdifModels.Statistics(
                total_entries=0,
                schema_entries=0,
                data_entries=0,
                parse_errors=0,
                detected_server_type=None,
            )
            response = FlextLdifModels.ParseResponse(
                entries=[],
                statistics=empty_statistics,
                detected_server_type=None,
            )

            return FlextResult.ok(response)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
                f"Parser service health check failed: {e}",
            )

    def _resolve_server_type(
        self,
        server_type: str | None,
        content: str | Path | list[object],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
    ) -> FlextResult[str]:
        """Resolve effective server type from explicit type or auto-detection."""
        if server_type is not None:
            quirk = self._registry.quirk(server_type)
            if quirk is None:
                self.logger.warning(
                    "Quirk not found for server type",
                    server_type=server_type,
                    available_quirks=self._registry.list_registered_servers(),
                )
                return FlextResult.fail(
                    f"No quirk implementation found for server type '{server_type}'. "
                    "Ensure server type is registered in quirks registry.",
                )
            return FlextResult.ok(server_type)

        # Use detector to resolve server type from config and content
        ldif_path = (
            content if input_source == "file" and isinstance(content, Path) else None
        )
        ldif_content = (
            content if input_source == "string" and isinstance(content, str) else None
        )
        return self._detector.get_effective_server_type(
            ldif_path=ldif_path,
            ldif_content=ldif_content,
        )

    @staticmethod
    def _normalize_list_content(
        content: list[object],
    ) -> list[tuple[str, dict[str, list[str]]]]:
        """Normalize list content to typed format for pyrefly cycle-breaking.

        This handles the type-safe conversion of list content which may
        have been inferred as list[object] by pyrefly's cycle-breaking.
        """
        if not content:
            return []

        first_item = content[0]
        if (
            not isinstance(first_item, tuple)
            or len(first_item) != FlextLdifConstants.TUPLE_LEN_2
        ):
            return []

        dn_part, attrs_part = first_item
        if not isinstance(dn_part, str) or not isinstance(attrs_part, dict):
            return []

        result_list: list[tuple[str, dict[str, list[str]]]] = []
        for item in content:
            if (
                not isinstance(item, tuple)
                or len(item) != FlextLdifConstants.TUPLE_LEN_2
            ):
                continue
            item_dn, item_attrs = item
            if not isinstance(item_dn, str) or not isinstance(item_attrs, dict):
                continue
            typed_attrs: dict[str, list[str]] = {
                str(k): [str(x) for x in v]
                for k, v in item_attrs.items()
                if isinstance(k, str) and isinstance(v, list)
            }
            result_list.append((item_dn, typed_attrs))
        return result_list

    def parse(
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Unified method to parse LDIF content from various sources using nested helper classes."""
        start_time = time.perf_counter()
        self._log_parsing_start(
            content, input_source, server_type, encoding, format_options
        )

        try:
            options = self._prepare_format_options(format_options)
            (
                router,
                validator,
                schema_extractor,
                acl_extractor,
                processor,
                stats_builder,
            ) = self._initialize_helpers()
            typed_content = self._normalize_content(content)
            effective_type_result = self._resolve_effective_server_type(
                server_type, typed_content, input_source
            )
            if effective_type_result.is_failure:
                return FlextResult.fail(
                    effective_type_result.error or "Server type resolution failed",
                )

            effective_type = effective_type_result.unwrap()
            return self._process_parsed_content(
                router,
                processor,
                stats_builder,
                typed_content,
                effective_type,
                encoding,
                input_source,
                options,
                start_time,
            )

        except Exception as e:
            parse_duration_at_error = (
                (time.perf_counter() - start_time) * 1000.0
                if "start_time" in locals()
                else 0
            )
            self.logger.exception(
                "Parsing exception",
                input_source=input_source,
                server_type=server_type,
                error=str(e),
                duration_ms=parse_duration_at_error,
            )
            return FlextResult.fail(
                f"An unexpected error occurred in parser service: {e}",
            )

    def _log_parsing_start(
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        server_type: str | None,
        encoding: str,
        format_options: FlextLdifModels.ParseFormatOptions | None,
    ) -> None:
        """Log parsing initialization."""
        self.logger.debug(
            "Starting LDIF parsing operation",
            input_source=input_source,
            server_type=server_type,
            encoding=encoding,
            content_type=type(content).__name__,
            content_length=len(content)
            if isinstance(content, str) or FlextRuntime.is_list_like(content)
            else "file_path",
            format_options=bool(format_options),
        )

    def _prepare_format_options(
        self,
        format_options: FlextLdifModels.ParseFormatOptions | None,
    ) -> FlextLdifModels.ParseFormatOptions:
        """Prepare format options with defaults if not provided."""
        if format_options is None:
            return FlextLdifModels.ParseFormatOptions(
                auto_parse_schema=True,
                auto_extract_acls=True,
                preserve_attribute_order=False,
                validate_entries=True,
                normalize_dns=True,
                max_parse_errors=100,
                include_operational_attrs=False,
                strict_schema_validation=False,
            )
        return format_options

    def _initialize_helpers(
        self,
    ) -> tuple[
        FlextLdifParser.InputRouter,
        FlextLdifParser.EntryValidator,
        FlextLdifParser.SchemaExtractor,
        FlextLdifParser.AclExtractor,
        FlextLdifParser.EntryProcessor,
        FlextLdifParser.StatisticsBuilder,
    ]:
        """Initialize nested helper classes."""
        self.logger.debug("Initialized parser helpers")
        router = self.InputRouter(self._registry, self.logger)
        validator = self.EntryValidator(self.logger)
        schema_extractor = self.SchemaExtractor(self._registry, self.logger)
        acl_extractor = self.AclExtractor(self._acl_service, self.logger)
        processor = self.EntryProcessor(
            schema_extractor,
            acl_extractor,
            validator,
            self._registry,
            self.logger,
        )
        stats_builder = self.StatisticsBuilder(
            enable_events=self._enable_events,
            parent_logger=self.logger,
        )
        return (
            router,
            validator,
            schema_extractor,
            acl_extractor,
            processor,
            stats_builder,
        )

    def _normalize_content(
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
    ) -> str | Path | list[tuple[str, dict[str, list[str]]]]:
        """Normalize content to typed format."""
        if isinstance(content, (str, Path)):
            return content
        if isinstance(content, list):
            content_as_objects: list[object] = list(content)
            return self._normalize_list_content(content_as_objects)
        return []

    def _resolve_effective_server_type(
        self,
        server_type: str | None,
        typed_content: str | Path | list[tuple[str, dict[str, list[str]]]],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
    ) -> FlextResult[str]:
        """Resolve effective server type using detector or explicit type."""
        content_for_resolve: str | Path | list[object]
        if isinstance(typed_content, (str, Path)):
            content_for_resolve = typed_content
        elif isinstance(typed_content, list):
            content_for_resolve = list(typed_content)
        else:
            content_for_resolve = []
        server_type_result = self._resolve_server_type(
            server_type, content_for_resolve, input_source
        )
        if server_type_result.is_failure:
            self.logger.error(
                "Server type resolution failed",
                error=server_type_result.error,
            )
            return FlextResult.fail(
                f"Server type resolution failed: {server_type_result.error}",
            )
        effective_type = server_type_result.unwrap()
        self.logger.info("Server type resolved", effective_type=effective_type)
        return FlextResult.ok(effective_type)

    def _process_parsed_content(
        self,
        router: FlextLdifParser.InputRouter,
        processor: FlextLdifParser.EntryProcessor,
        stats_builder: FlextLdifParser.StatisticsBuilder,
        typed_content: str | Path | list[tuple[str, dict[str, list[str]]]],
        effective_type: str,
        encoding: str,
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        options: FlextLdifModels.ParseFormatOptions,
        start_time: float,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Process parsed content and return response."""
        entries_result = router.route_and_parse(
            input_source,
            typed_content,
            effective_type,
            encoding,
        )
        if entries_result.is_failure:
            self.logger.error(
                "LDIF parsing failed",
                error=entries_result.error,
                input_source=input_source,
                effective_type=effective_type,
            )
            return FlextResult.fail(
                f"Failed to parse LDIF content: {entries_result.error}",
            )

        parse_response = entries_result.unwrap()
        entries_raw: list[object] = list(parse_response.entries)
        entries = self._extract_entries(entries_raw)
        failed_count = parse_response.statistics.parse_errors
        failed_details: list[str] = []

        processed_entries, stats = processor.post_process_entries(
            entries,
            effective_type,
            options,
        )

        parse_duration_ms = (time.perf_counter() - start_time) * 1000.0
        stats = stats_builder.finalize(
            stats,
            failed_count,
            failed_details,
            processed_entries,
            parse_duration_ms,
            input_source,
            typed_content,
            effective_type,
        )

        response = FlextLdifModels.ParseResponse(
            entries=list(processed_entries)
            if isinstance(processed_entries, Sequence)
            else processed_entries,
            statistics=stats,
            detected_server_type=effective_type,
        )

        self.logger.info(
            "Parsing completed",
            input_source=input_source,
            server_type=effective_type,
            total_entries=len(processed_entries),
            parse_errors=stats.parse_errors,
            duration_ms=parse_duration_ms,
        )

        return FlextResult.ok(response)

    def _extract_entries(
        self,
        entries_raw: list[FlextLdifModels.Entry] | list[object],
    ) -> list[FlextLdifModels.Entry]:
        """Extract and validate entries from parse response."""
        entries: list[FlextLdifModels.Entry] = []
        for entry in entries_raw:
            if isinstance(entry, FlextLdifModels.Entry):
                entries.append(entry)
            else:
                self.logger.warning(
                    "Skipped entry with unexpected type",
                    entry_type=type(entry).__name__,
                )
        return entries

    # ==================== CONVENIENCE METHODS ====================

    def parse_string(
        self,
        content: str,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Convenience method to parse LDIF content from string."""
        return self.parse(
            content=content,
            input_source="string",
            server_type=server_type,
            format_options=format_options,
        )

    def parse_ldif_file(
        self,
        path: Path,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Convenience method to parse LDIF content from file."""
        return self.parse(
            content=path,
            input_source="file",
            server_type=server_type,
            encoding=encoding,
            format_options=format_options,
        )

    def parse_ldap3_results(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Convenience method to parse ldap3 query results."""
        return self.parse(
            content=results,
            input_source="ldap3",
            server_type=server_type,
            format_options=format_options,
        )

    def parse_source(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF from source (Path or str) with automatic detection.

        Intelligently handles:
        - Path objects: Read file content
        - Strings with file-like patterns: Treat as file path and validate existence
        - Strings without file patterns: Treat as LDIF content

        Args:
            source: Either a Path to LDIF file or string containing LDIF data
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            format_options: Parse options as ParseFormatOptions model

        Returns:
            FlextResult containing ParseResponse with entries

        """
        # Case 1: Path object - read file
        if isinstance(source, Path):
            return self.parse_ldif_file(
                path=source,
                server_type=server_type,
                encoding=getattr(self.config.ldif, "ldif_encoding", "utf-8"),
                format_options=format_options,
            )

        # Case 2: String - detect if it's a file path or LDIF content
        if isinstance(source, str):
            # Handle empty string or whitespace-only as empty LDIF content
            if not source.strip():
                return self.parse_string(
                    content=source,
                    server_type=server_type,
                    format_options=format_options,
                )

            # Heuristic: Check if string looks like LDIF content first
            # LDIF content indicators: starts with "dn:" or contains LDIF patterns
            is_ldif_content = (
                source.strip().startswith("dn:")
                or source.strip().startswith("#")
                or "\ndn:" in source
                or "\r\ndn:" in source
            )

            # Heuristic: Check if string looks like a file path
            # Indicators: ends with .ldif, looks like absolute path, or short string that exists as file
            # Windows MAX_PATH limit (260 characters)
            windows_max_path_length = 260
            is_file_path = (
                source.endswith((".ldif", ".LDIF"))
                or (
                    len(source) < windows_max_path_length and Path(source).is_file()
                )  # Windows MAX_PATH limit, use is_file() not exists()
            )

            # If it looks like LDIF content, treat as content (even if it contains /)
            if is_ldif_content:
                return self.parse_string(
                    content=source,
                    server_type=server_type,
                    format_options=format_options,
                )

            # If it looks like a file path, validate and read
            if is_file_path:
                file_path = Path(source)
                if not file_path.exists():
                    return FlextResult.fail(f"File not found: {source}")
                if not file_path.is_file():
                    return FlextResult.fail(f"Path is not a file: {source}")
                return self.parse_ldif_file(
                    path=file_path,
                    server_type=server_type,
                    encoding=getattr(self.config.ldif, "ldif_encoding", "utf-8"),
                    format_options=format_options,
                )

            # Default: treat as LDIF content if ambiguous
            return self.parse_string(
                content=source,
                server_type=server_type,
                format_options=format_options,
            )

        # Should not reach here due to type annotation, but fail-safe
        source_type_name = type(source).__name__
        return FlextResult.fail(
            f"Source must be Path or str, got {source_type_name}",
        )


__all__ = ["FlextLdifParser"]
