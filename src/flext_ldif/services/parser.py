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

# Python 3.13 compatibility: Ensure ldif3 library compatibility
# Note: ldif3 should be updated to use base64.decodebytes instead of deprecated decodestring
# This is handled by the ldif3 library itself
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifParser(FlextService[Any]):
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

    _logger: FlextLogger
    _config: FlextLdifConfig
    _registry: FlextLdifServer
    _acl_service: FlextLdifAcl
    _detector: FlextLdifDetector

    def __init__(
        self,
        config: FlextLdifConfig | None = None,
        *,
        enable_events: bool = False,
    ) -> None:
        """Initialize parser service with direct quirks usage.

        Args:
            config: Optional FlextLdifConfig instance. If None, uses default config.
            enable_events: Enable domain event emission (default: False for backward compatibility).

        Initializes:
            - FlextLdifServer: For all parsing modes (RFC/server-specific/relaxed)
            - FlextLdifAcl: For ACL extraction
            - FlextLdifDetector: For server type detection

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._logger = FlextLogger(__name__)
        self._enable_events = enable_events

        # Initialize parsing components
        self._registry = FlextLdifServer()
        self._acl_service = FlextLdifAcl()
        self._detector = FlextLdifDetector()

    def _create_parse_event(
        self,
        processed_entries: list[FlextLdifModels.Entry],
        parse_duration_ms: float,
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        effective_type: str,
        failed_count: int,
        failed_details: list[str],
    ) -> FlextLdifModels.ParseEvent:
        """Create ParseEvent with current parsing metrics.

        Args:
            processed_entries: List of parsed entries
            parse_duration_ms: Duration of parse operation in milliseconds
            input_source: Type of input source (file/string/ldap3)
            content: Original content passed to parse
            effective_type: Detected or configured server type
            failed_count: Number of failed entries
            failed_details: Details of failed entries

        Returns:
            ParseEvent with all metrics populated

        """
        # Count schema entries vs data entries
        schema_count = sum(
            1 for entry in processed_entries if "cn=schema" in str(entry.dn).lower()
        )
        data_count = len(processed_entries) - schema_count

        # Determine source file path
        source_file = (
            str(content)
            if input_source == "file" and isinstance(content, Path)
            else None
        )

        # Create and return ParseEvent with DomainEvent required fields
        return FlextLdifModels.ParseEvent(
            unique_id=f"parse_{uuid.uuid4().hex[:8]}",
            event_type="ldif.parse",
            aggregate_id=source_file or f"parse_{uuid.uuid4().hex[:8]}",
            created_at=datetime.now(UTC),
            entries_parsed=len(processed_entries),
            schema_entries=schema_count,
            data_entries=data_count,
            parse_duration_ms=parse_duration_ms,
            source_file=source_file,
            source_type=input_source,
            detected_server_type=effective_type,
            detection_confidence=1.0,
            quirks_applied=[],
            errors_encountered=failed_details if failed_count > 0 else [],
            fatal_errors=[],
        )

    @override
    def execute(self) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Execute parser service health check.

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

            return FlextResult[FlextLdifModels.ParseResponse].ok(response)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ParseResponse].fail(
                f"Parser service health check failed: {e}",
            )

    def parse(  # noqa: C901
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Unified method to parse LDIF content from various sources."""
        # Start timing for event metrics
        start_time = time.perf_counter()

        try:
            options = format_options or FlextLdifModels.ParseFormatOptions()

            # Resolve effective server type based on configuration and auto-detection
            ldif_path = (
                content
                if input_source == "file" and isinstance(content, Path)
                else None
            )
            ldif_content = (
                content
                if input_source == "string" and isinstance(content, str)
                else None
            )

            server_type_result = self._resolve_server_type(
                server_type=server_type,
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if server_type_result.is_failure:
                return FlextResult.fail(
                    f"Server type resolution failed: {server_type_result.error}",
                )

            effective_type = server_type_result.unwrap()
            entries_result: (
                FlextResult[list[FlextLdifModels.Entry]]
                | FlextResult[tuple[list[FlextLdifModels.Entry], int, list[str]]]
            )

            if input_source == "string" and isinstance(content, str):
                entries_result = self._parse_from_string(content, effective_type)
            elif input_source == "file" and isinstance(content, Path):
                entries_result = self._parse_from_file(
                    content,
                    encoding,
                    effective_type,
                )
            elif input_source == "ldap3":
                if not isinstance(content, list):
                    return FlextResult.fail("ldap3 input source requires list content")
                entries_result = self._parse_from_ldap3(
                    content,
                    effective_type,
                )
            else:
                return FlextResult.fail(f"Unsupported input source: {input_source}")

            if entries_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse LDIF content: {entries_result.error}",
                )

            # Unpack tuple: (entries, failed_count, failed_details) for ldap3 source
            entries_data = entries_result.unwrap()
            if input_source == "ldap3" and isinstance(entries_data, tuple):
                entries, failed_count, failed_details = entries_data
            else:
                entries = cast("list[FlextLdifModels.Entry]", entries_data)
                failed_count = 0
                failed_details = []

            processed_entries, stats = self._post_process_entries(
                entries,
                effective_type,
                options,
            )

            # Update parse_errors in statistics with failures from ldap3 parsing
            if failed_count > 0:
                stats = stats.model_copy(
                    update={"parse_errors": stats.parse_errors + failed_count},
                )
                # Log critical summary
                self._logger.error(
                    f"Parse completed with {failed_count} entry failures. "
                    f"See details in parse_errors field. Failed entries: {failed_details[:5]}"  # Log first 5
                )

            # Calculate parse duration
            parse_duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Emit ParseEvent if enabled
            if self._enable_events:
                parse_event = self._create_parse_event(
                    processed_entries=processed_entries,
                    parse_duration_ms=parse_duration_ms,
                    input_source=input_source,
                    content=content,
                    effective_type=effective_type,
                    failed_count=failed_count,
                    failed_details=failed_details,
                )
                stats = stats.add_event(parse_event)

            response = FlextLdifModels.ParseResponse(
                entries=processed_entries,
                statistics=stats,
                detected_server_type=effective_type,
            )
            return FlextResult.ok(response)

        except Exception as e:
            return FlextResult.fail(
                f"An unexpected error occurred in parser service: {e}",
            )

    def _parse_from_string(
        self,
        content: str,
        server_type: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        # Get the appropriate entry quirk for this server type from registry
        # Entry quirks handle LDIF content parsing via entry.parse_content method
        quirks = self._registry.get_entrys(server_type)
        if not quirks:
            return FlextResult.fail(
                f"Internal error: No entry quirk found for resolved server type '{server_type}'",
            )

        # Use the first (highest priority) entry quirk for this server type
        # Note: get_entrys() returns Entry instances directly, not base quirks
        entry = quirks[0]

        # Use public parse() interface to parse LDIF content
        return entry.parse(content)

    def _parse_from_file(
        self,
        path: Path,
        encoding: str,
        server_type: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        if not path.exists():
            return FlextResult.fail(f"LDIF file not found: {path}")
        try:
            content = path.read_text(encoding=encoding)
            return self._parse_from_string(content, server_type)
        except (FileNotFoundError, OSError, Exception) as e:
            return FlextResult.fail(f"Failed to read LDIF file: {e}")

    def _parse_from_ldap3(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str,
    ) -> FlextResult[tuple[list[FlextLdifModels.Entry], int, list[str]]]:
        """Parse LDAP3 search results into Entry models.

        Uses the quirk's entry parsing to properly create Entry models
        from LDAP3 format (dn, attributes) tuples.
        """
        quirks = self._registry.gets(server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk available for server type: {server_type}",
            )
        quirk = quirks[0]

        entries = []
        failed_count = 0
        failed_details: list[str] = []

        for dn, attrs in results:
            # Use quirk's _parse_entry method to properly create Entry model
            # This ensures proper DN and attributes handling per server type
            entry_result = quirk.entry_quirk.parse_entry(dn, attrs)

            if entry_result.is_success:
                entries.append(entry_result.unwrap())
            else:
                # Count and log failures - CRITICAL: do not silently drop entries!
                failed_count += 1
                error_msg = f"DN: {dn}, Error: {entry_result.error}"
                failed_details.append(error_msg)
                self._logger.error(
                    f"FAILED to parse LDAP3 entry {dn}: {entry_result.error}",
                )

        # Log summary if there were failures
        if failed_count > 0:
            self._logger.error(
                f"LDAP3 parse completed with {failed_count} FAILURES out of {len(results)} total entries. "
                f"Successful: {len(entries)}, Failed: {failed_count}",
            )

        # Return tuple with success entries and failure count for statistics
        return FlextResult.ok((entries, failed_count, failed_details))

    def _validate_explicit_server_type(self, server_type: str) -> FlextResult[str]:
        """Validate explicitly provided server type."""
        quirks = self._registry.gets(server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk implementation found for explicitly specified server type '{server_type}'. "
                f"Please ensure the server type is registered in the quirks registry.",
            )
        return FlextResult.ok(server_type)

    def _resolve_auto_detection(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[str]:
        """Resolve server type using auto-detection."""
        if ldif_path or ldif_content:
            detection_result = self._detector.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if detection_result.is_success:
                detected_data = detection_result.unwrap()
                detected_type = detected_data.detected_server_type
                if detected_type:
                    self._logger.info("Auto-detected server type: %s", detected_type)
                    return FlextResult.ok(detected_type)

        self._logger.warning(
            "Auto-detection failed or no content provided, using RELAXED mode",
        )
        return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

    def _resolve_server_type(
        self,
        server_type: str | None,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[str]:
        """Resolve the effective server type based on configuration and auto-detection.

        Resolution priority:
        1. Explicitly provided server_type (hard errors if invalid)
        2. Relaxed mode (if enabled in config)
        3. Manual mode (uses configured server type)
        4. Auto-detection mode (detects from content/file)
        5. Fallback to configured default or RELAXED

        Args:
            server_type: Explicitly provided server type (takes precedence)
            ldif_path: Optional path for auto-detection
            ldif_content: Optional content for auto-detection

        Returns:
            FlextResult with resolved server type string

        """
        try:
            if server_type is not None:
                return self._validate_explicit_server_type(server_type)

            config = self._config

            if config.enable_relaxed_parsing:
                return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

            if config.quirks_detection_mode == "manual":
                if config.quirks_server_type:
                    return FlextResult.ok(config.quirks_server_type)
                return FlextResult.fail(
                    "Manual mode requires quirks_server_type to be set in configuration",
                )

            if config.quirks_detection_mode == "auto":
                return self._resolve_auto_detection(ldif_path, ldif_content)

            default_type = getattr(
                config,
                "ldif_default_server_type",
                FlextLdifConstants.ServerTypes.RELAXED,
            )
            return FlextResult.ok(default_type)

        except (ValueError, TypeError, AttributeError):
            self._logger.exception("Error resolving server type")
            return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

    def _process_single_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> tuple[FlextLdifModels.Entry, int, int, list[str]]:
        """Process single entry with all transformations.

        Returns: (processed_entry, schema_count, data_count, validation_errors)
        """
        processed_entry = entry
        schema_count = 0
        data_count = 0
        validation_errors = []

        if options.normalize_dns:
            processed_entry = self._normalize_entry_dn(processed_entry)

        if options.auto_parse_schema and self._is_schema_entry(processed_entry):
            schema_count = 1
            processed_entry = self._parse_schema_entry(processed_entry, server_type)
        else:
            data_count = 1

        if options.auto_extract_acls:
            processed_entry = self._extract_acls(processed_entry, server_type)

        if options.validate_entries:
            validation_result = self._validate_entry(
                processed_entry,
                strict=options.strict_schema_validation,
            )
            if validation_result.is_failure:
                if options.strict_schema_validation:
                    msg = f"Strict validation failed for entry {processed_entry.dn}: {validation_result.error}"
                    raise ValueError(msg)
                self._logger.warning(
                    f"Entry validation warning for {processed_entry.dn}: {validation_result.error}",
                )
                validation_errors.append(validation_result.error)

        if not options.include_operational_attrs:
            processed_entry = self._filter_operational_attributes(processed_entry)

        # Filter out None values from validation_errors
        filtered_errors = [e for e in validation_errors if e is not None]
        return processed_entry, schema_count, data_count, filtered_errors

    def _post_process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> tuple[list[FlextLdifModels.Entry], FlextLdifModels.Statistics]:
        processed_entries = []
        schema_count = 0
        data_count = 0
        parse_errors = 0
        validation_errors = []

        for entry in entries:
            try:
                processed_entry, schema_inc, data_inc, val_errs = (
                    self._process_single_entry(entry, server_type, options)
                )
                schema_count += schema_inc
                data_count += data_inc
                validation_errors.extend(val_errs)
                processed_entries.append(processed_entry)

            except Exception as e:
                parse_errors += 1
                error_msg = f"Error processing entry {entry.dn if hasattr(entry, 'dn') else 'unknown'}: {e}"
                self._logger.exception(error_msg)

                if (
                    options.max_parse_errors > 0
                    and parse_errors >= options.max_parse_errors
                ):
                    self._logger.exception(
                        f"Maximum parse errors ({options.max_parse_errors}) reached, stopping processing",
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

    def _normalize_entry_dn(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Normalize DN formatting to RFC 4514 standard using FlextLdifUtilities."""
        try:
            # Use FlextLdifUtilities.DN for RFC 4514 compliant DN normalization
            dn_str = str(entry.dn.value)
            normalized_str = FlextLdifUtilities.DN.norm(dn_str)

            # Fallback to clean_dn if norm returns None
            if normalized_str is None:
                normalized_str = FlextLdifUtilities.DN.clean_dn(dn_str)

            # Create new entry with normalized DN
            normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_str)

            # Create new entry with normalized DN
            entry_dict = entry.model_dump()
            entry_dict["dn"] = normalized_dn
            return FlextLdifModels.Entry.model_validate(entry_dict)
        except Exception as e:
            self._logger.warning(f"Failed to normalize DN for entry {entry.dn}: {e}")
            return entry

    def _validate_entry(
        self,
        entry: FlextLdifModels.Entry,
        *,
        strict: bool = False,
    ) -> FlextResult[bool]:
        """Validate entry against LDAP schema rules using FlextLdifUtilities."""
        try:
            validation_errors: list[str] = []

            # Validate DN
            self._validate_entry_dn(entry, validation_errors)

            # Validate objectClass
            self._validate_entry_objectclass(
                entry, strict=strict, errors=validation_errors
            )

            # Validate attribute values
            self._validate_entry_attributes(
                entry, strict=strict, errors=validation_errors
            )

            if validation_errors:
                return FlextResult.fail("; ".join(validation_errors))

            return FlextResult.ok(True)

        except Exception as e:
            return FlextResult.fail(f"Validation error: {e}")

    def _validate_entry_dn(
        self,
        entry: FlextLdifModels.Entry,
        errors: list[str],
    ) -> None:
        """Validate entry DN.

        Args:
            entry: Entry to validate
            errors: List to append error messages to

        """
        dn_str = str(entry.dn.value) if entry.dn else None
        if not dn_str:
            errors.append("Entry DN cannot be empty")
        elif not FlextLdifUtilities.DN.validate(dn_str):
            errors.append(f"Invalid DN format per RFC 4514: {dn_str}")

    def _validate_entry_objectclass(
        self,
        entry: FlextLdifModels.Entry,
        *,
        strict: bool,
        errors: list[str],
    ) -> None:
        """Validate entry has objectClass attribute.

        Args:
            entry: Entry to validate
            strict: Whether to enforce objectClass requirement
            errors: List to append error messages to

        """
        has_objectclass = any(
            attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower()
            for attr_name in entry.attributes.attributes
        )
        if not has_objectclass and strict:
            errors.append("Entry must have objectClass attribute")

    def _validate_entry_attributes(
        self,
        entry: FlextLdifModels.Entry,
        *,
        strict: bool,
        errors: list[str],
    ) -> None:
        """Validate entry attribute values.

        Args:
            entry: Entry to validate
            strict: Whether to check for empty values
            errors: List to append error messages to

        """
        for attr_name, attr_value in entry.attributes.attributes.items():
            if isinstance(attr_value, list):
                values = attr_value
            elif hasattr(attr_value, "values") and isinstance(
                attr_value.values,
                list,
            ):
                values = attr_value.values
            else:
                values = [attr_value]

            if (not values or all(not v for v in values)) and strict:
                errors.append(f"Attribute '{attr_name}' has empty values")

    def _filter_operational_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Filter out operational attributes from entry.

        IMPORTANT: For schema entries, preserve attributetypes and objectclasses
        as they are the core content of schema entries and needed for filtering.
        """
        try:
            # Check if this is a schema entry - if so, preserve schema attributes
            is_schema_entry = self._is_schema_entry(entry)

            # Common operational attributes to filter from ALL entries
            # These are always filtered regardless of entry type
            operational_attrs = {
                attr.lower()
                for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_ALL_ENTRIES
            }

            # Schema-related attributes should ONLY be filtered for non-schema entries
            # For schema entries, these are the actual content, not operational attributes
            if not is_schema_entry:
                schema_operational_attrs = {
                    attr.lower()
                    for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_NON_SCHEMA_ENTRIES
                }
                operational_attrs.update(schema_operational_attrs)

            # Filter attributes
            filtered_attrs = {
                attr_name: attr_value
                for attr_name, attr_value in entry.attributes.attributes.items()
                if attr_name.lower() not in operational_attrs
            }

            # Create new LdifAttributes with filtered attributes
            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=filtered_attrs,
                attribute_metadata=entry.attributes.attribute_metadata,
                metadata=entry.attributes.metadata,
            )

            # Return entry with filtered attributes
            return entry.model_copy(update={"attributes": new_attributes})

        except Exception as e:
            self._logger.warning(
                f"Failed to filter operational attributes for entry {entry.dn}: {e}",
            )
            return entry

    # ==================== AUTOMATIC INTERNAL METHODS ====================

    def _is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema subentry (AUTOMATIC detection).

        Uses FlextLdifUtilities.Entry.is_schema_entry() with permissive mode
        (strict=False) to accept entries matching ANY of:
        - DN pattern (cn=subschemasubentry, cn=subschema)
        - ObjectClass (subschema, subentry)
        - Schema attributes (attributetypes, objectclasses)

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema subentry, False otherwise

        """
        return FlextLdifUtilities.Entry.is_schema_entry(entry, strict=False)

    def _parse_attribute_types_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        schemas: list[FlextLdifServersBase],
    ) -> list[FlextLdifModels.SchemaAttribute]:
        """Parse attributeTypes from entry using schema quirks."""
        schema_attributes = []
        attr_types = entry.attributes.get(
            FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
            [],
        )
        if attr_types:
            for attr_def in attr_types:
                for quirk in schemas:
                    if quirk.schema_quirk.can_handle_attribute(attr_def):
                        result = quirk.schema_quirk.parse_attribute(attr_def)
                        if result.is_success:
                            schema_attributes.append(result.unwrap())
                            break
        return schema_attributes

    def _parse_objectclasses_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        schemas: list[FlextLdifServersBase],
    ) -> list[FlextLdifModels.SchemaObjectClass]:
        """Parse objectClasses from entry using schema quirks."""
        schema_objectclasses = []
        obj_classes = entry.attributes.get(
            FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
            [],
        )
        if obj_classes:
            for oc_def in obj_classes:
                for quirk in schemas:
                    if quirk.schema_quirk.can_handle_objectclass(oc_def):
                        oc_result = quirk.schema_quirk.parse_objectclass(oc_def)
                        if oc_result.is_success:
                            schema_objectclasses.append(oc_result.unwrap())
                            break
        return schema_objectclasses

    def _parse_schema_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Parse schema entry attributes into models (AUTOMATIC internal).

        Args:
            entry: Entry to parse
            server_type: Server type for quirk selection

        Returns:
            Entry with populated attributes_schema and objectclasses

        """
        try:
            schemas = self._registry.gets(server_type)
            if not schemas:
                schemas = self._registry.gets(
                    FlextLdifConstants.ServerTypes.RFC,
                )

            schema_attributes = self._parse_attribute_types_from_entry(entry, schemas)
            schema_objectclasses = self._parse_objectclasses_from_entry(entry, schemas)

            return entry.model_copy(
                update={
                    "attributes_schema": (schema_attributes or None),
                    "objectclasses": (schema_objectclasses or None),
                },
            )

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self._logger.warning("Error parsing schema entry: %s", e)
            return entry

    def _extract_acls(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Extract ACLs from entry attributes (AUTOMATIC internal).

        Args:
            entry: Entry to extract ACLs from
            server_type: Server type for quirk selection

        Returns:
            Entry with Entry.acls populated if ACLs found

        """
        try:
            acl_result = self._acl_service.extract_acls_from_entry(
                entry,
                server_type=server_type,
            )

            if acl_result.is_success and acl_result.value:
                # Extract just the acls list from AclResponse
                acl_response = acl_result.value
                if acl_response.acls:
                    return entry.model_copy(update={"acls": acl_response.acls})

            return entry

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self._logger.warning("Error extracting ACLs: %s", e)
            return entry

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


__all__ = ["FlextLdifParser"]
