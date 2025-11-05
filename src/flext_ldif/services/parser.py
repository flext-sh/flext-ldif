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

from pathlib import Path
from typing import Any, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities

# Python 3.13 compatibility: Ensure ldif3 library compatibility
# Note: ldif3 should be updated to use base64.decodebytes instead of deprecated decodestring
# This is handled by the ldif3 library itself


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
    ) -> None:
        """Initialize parser service with direct quirks usage.

        Args:
            config: Optional FlextLdifConfig instance. If None, uses default config.

        Initializes:
            - FlextLdifServer: For all parsing modes (RFC/server-specific/relaxed)
            - FlextLdifAcl: For ACL extraction
            - FlextLdifDetector: For server type detection

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._logger = FlextLogger(__name__)

        # Initialize parsing components
        self._registry = FlextLdifServer()
        self._acl_service = FlextLdifAcl()
        self._detector = FlextLdifDetector()

    @override
    def execute(self) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Execute parser service health check.

        Returns:
            FlextResult with empty ParseResponse (service status check only).

        """
        try:
            # Health check - return empty ParseResponse indicating operational status
            empty_statistics = FlextLdifModels.ParseStatistics(
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

    def parse(
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Unified method to parse LDIF content from various sources."""
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
            entries_result: FlextResult[list[FlextLdifModels.Entry]]

            if input_source == "string" and isinstance(content, str):
                entries_result = self._parse_from_string(content, effective_type)
            elif input_source == "file" and isinstance(content, Path):
                entries_result = self._parse_from_file(
                    content,
                    encoding,
                    effective_type,
                )
            elif input_source == "ldap3":
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

            entries = entries_result.unwrap()
            processed_entries, stats = self._post_process_entries(
                entries,
                effective_type,
                options,
            )

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
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDAP3 search results into Entry models.

        Uses the quirk's entry parsing to properly create Entry models
        from LDAP3 format (dn, attributes) tuples.
        """
        quirks = self._registry.gets(server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk available for server type: {server_type}",
            )
        quirk: FlextLdifProtocols.Quirks.QuirksPort = quirks[0]

        entries = []
        for dn, attrs in results:
            # Use quirk's _parse_entry method to properly create Entry model
            # This ensures proper DN and attributes handling per server type
            entry_result = quirk.entry._parse_entry(dn, attrs)

            if entry_result.is_success:
                entries.append(entry_result.unwrap())
            else:
                # Log warning but continue processing other entries
                self._logger.warning(
                    f"Failed to parse LDAP3 entry {dn}: {entry_result.error}",
                )

        return FlextResult.ok(entries)

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

        except (ValueError, TypeError, AttributeError) as e:
            self._logger.exception("Error resolving server type: %s", e)
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

        return processed_entry, schema_count, data_count, validation_errors

    def _post_process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> tuple[list[FlextLdifModels.Entry], FlextLdifModels.ParseStatistics]:
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

        statistics = FlextLdifModels.ParseStatistics(
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
            # Basic entry validation
            validation_errors = []

            # 1. Check DN is not empty using FlextLdifUtilities.DN validation
            dn_str = str(entry.dn.value) if entry.dn else None
            if not dn_str:
                validation_errors.append("Entry DN cannot be empty")
            elif not FlextLdifUtilities.DN.validate(dn_str):
                validation_errors.append(f"Invalid DN format per RFC 4514: {dn_str}")

            # 2. Check for required objectClass attribute
            # Note: objectClass may be removed/transformed by quirks during migration
            # Only warn in strict mode, not in normal validation
            has_objectclass = any(
                attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower()
                for attr_name in entry.attributes.attributes
            )
            if not has_objectclass and strict:
                validation_errors.append("Entry must have objectClass attribute")

            # 3. Check for empty attribute values (optional validation)
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

                if not values or all(not v for v in values):
                    if strict:
                        validation_errors.append(
                            f"Attribute '{attr_name}' has empty values",
                        )

            if validation_errors:
                return FlextResult.fail("; ".join(validation_errors))

            return FlextResult.ok(True)

        except Exception as e:
            return FlextResult.fail(f"Validation error: {e}")

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
        schemas: list,
    ) -> list:
        """Parse attributeTypes from entry using schema quirks."""
        schema_attributes = []
        attr_types = entry.attributes.get(
            FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
            [],
        )
        if attr_types:
            for attr_def in attr_types:
                for quirk in schemas:
                    if quirk.schema.can_handle_attribute(attr_def):
                        result = quirk.schema.parse_attribute(attr_def)
                        if result.is_success:
                            schema_attributes.append(result.unwrap())
                            break
        return schema_attributes

    def _parse_objectclasses_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        schemas: list,
    ) -> list:
        """Parse objectClasses from entry using schema quirks."""
        schema_objectclasses = []
        obj_classes = entry.attributes.get(
            FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
            [],
        )
        if obj_classes:
            for oc_def in obj_classes:
                for quirk in schemas:
                    if quirk.schema.can_handle_objectclass(oc_def):
                        oc_result = quirk.schema.parse_objectclass(oc_def)
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
            schemas = self._registry.get_schemas(server_type)
            if not schemas:
                schemas = self._registry.get_schemas(
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

    def parse_file(
        self,
        path: Path,
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file and return entries directly.

        This method is a convenience wrapper around parse_ldif_file that
        returns entries directly instead of ParseResponse, for backward
        compatibility with existing tests.

        Note: This method name intentionally conflicts with Pydantic BaseModel.parse_file,
        but serves a different purpose (parsing LDIF files, not Pydantic model files).
        The type: ignore comment is used to suppress the override warning.

        Args:
            path: Path to LDIF file to parse
            server_type: Optional server type (auto-detected if not provided)
            encoding: File encoding (default: utf-8)
            format_options: Optional parsing format options

        Returns:
            FlextResult containing list of parsed entries

        Example:
            >>> parser = FlextLdifParser()
            >>> result = parser.parse_file(Path("directory.ldif"))
            >>> if result.is_success:
            ...     entries = result.unwrap()

        """
        parse_result = self.parse_ldif_file(
            path=path,
            server_type=server_type,
            encoding=encoding,
            format_options=format_options,
        )

        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error)

        parse_response = parse_result.unwrap()
        return FlextResult.ok(parse_response.entries)


__all__ = ["FlextLdifParser"]
