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
from typing import Any, Literal, cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.server_detector import FlextLdifServerDetector

# Python 3.13 compatibility: Ensure ldif3 library compatibility
# Note: ldif3 should be updated to use base64.decodebytes instead of deprecated decodestring
# This is handled by the ldif3 library itself


class FlextLdifParserService(FlextService[Any]):
    r"""LDIF parsing service - PARSING ONLY.

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
        - Writing: Use FlextLdifWriterService
        - Migration: Use FlextLdifMigrationPipeline
        - Server detection: Use FlextLdifServerDetector (used internally)

    Architecture:
        - Direct quirks usage without wrapper classes
        - Entry quirks decode LDIF → Entry models
        - Schema quirks decode schema lines → SchemaAttribute/SchemaObjectClass
        - ACL quirks decode ACL attributes → Acl models
        - Uses FlextLdifRegistry for ALL modes (RFC/server-specific/relaxed)
        - Returns FlextResult[list[Entry]] - always consistent type
        - Type-safe with Python 3.13+ annotations

    Example:
        >>> from flext_ldif.services.parser import FlextLdifParserService
        >>>
        >>> # Initialize parser service
        >>> parser = FlextLdifParserService()
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
    _quirk_registry: FlextLdifRegistry
    _acl_service: FlextLdifAclService
    _server_detector: FlextLdifServerDetector

    def __init__(
        self,
        config: FlextLdifConfig | None = None,
    ) -> None:
        """Initialize parser service with direct quirks usage.

        Args:
            config: Optional FlextLdifConfig instance. If None, uses default config.

        Initializes:
            - FlextLdifRegistry: For all parsing modes (RFC/server-specific/relaxed)
            - FlextLdifAclService: For ACL extraction
            - FlextLdifServerDetector: For server type detection

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._logger = FlextLogger(__name__)

        # Initialize parsing components
        self._quirk_registry = FlextLdifRegistry()
        self._acl_service = FlextLdifAclService()
        self._server_detector = FlextLdifServerDetector()

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
        input_source: Literal["string", "file", "ldap3"],
        server_type: str | None = None,
        encoding: str = "utf-8",
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Unified method to parse LDIF content from various sources."""
        try:
            options = format_options or FlextLdifModels.ParseFormatOptions()

            # Resolve effective server type based on configuration and auto-detection
            ldif_path = cast("Path", content) if input_source == "file" else None
            ldif_content = cast("str", content) if input_source == "string" else None

            server_type_result = self._resolve_server_type(
                server_type=server_type,
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if server_type_result.is_failure:
                return FlextResult.fail(
                    f"Server type resolution failed: {server_type_result.error}"
                )

            effective_type = server_type_result.unwrap()
            entries_result: FlextResult[list[FlextLdifModels.Entry]]

            if input_source == "string":
                entries_result = self._parse_from_string(
                    cast("str", content), effective_type, options
                )
            elif input_source == "file":
                entries_result = self._parse_from_file(
                    cast("Path", content), encoding, effective_type, options
                )
            elif input_source == "ldap3":
                entries_result = self._parse_from_ldap3(
                    cast("list[tuple[str, dict[str, list[str]]]]", content),
                    effective_type,
                    options,
                )
            else:
                return FlextResult.fail(f"Unsupported input source: {input_source}")

            if entries_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse LDIF content: {entries_result.error}"
                )

            entries = entries_result.unwrap()
            processed_entries, stats = self._post_process_entries(
                entries, effective_type, options
            )

            response = FlextLdifModels.ParseResponse(
                entries=processed_entries,
                statistics=stats,
                detected_server_type=effective_type,
            )
            return FlextResult.ok(response)

        except Exception as e:
            return FlextResult.fail(
                f"An unexpected error occurred in parser service: {e}"
            )

    def _parse_from_string(
        self,
        content: str,
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        # Use FlextLdifRegistry to get the appropriate quirk
        # Server type is now properly resolved upstream, so this should always succeed
        quirks = self._quirk_registry.get_quirks(server_type)
        if not quirks:
            return FlextResult.fail(
                f"Internal error: No quirk found for resolved server type '{server_type}'"
            )

        # Use the first available quirk for this server type
        quirk = quirks[0]

        # Apply preserve_attribute_order option if supported by quirk
        if options.preserve_attribute_order:
            try:
                return quirk.parse_ldif_content(content, preserve_attribute_order=True)
            except TypeError:
                # Fallback for quirks that don't support preserve_attribute_order
                self._logger.warning(
                    f"Quirk {type(quirk).__name__} doesn't support preserve_attribute_order option"
                )
                return quirk.parse_ldif_content(content)
        else:
            return quirk.parse_ldif_content(content)

    def _parse_from_file(
        self,
        path: Path,
        encoding: str,
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        if not path.exists():
            return FlextResult.fail(f"LDIF file not found: {path}")
        try:
            content = path.read_text(encoding=encoding)
            return self._parse_from_string(content, server_type, options)
        except (FileNotFoundError, OSError, Exception) as e:
            return FlextResult.fail(f"Failed to read LDIF file: {e}")

    def _parse_from_ldap3(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        quirks = self._quirk_registry.get_quirks(server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk available for server type: {server_type}"
            )
        quirk: FlextLdifProtocols.Quirks.QuirksPort = quirks[0]

        entries = []
        for dn, attrs in results:
            # Manually create a barebones Entry to normalize
            raw_entry = FlextLdifModels.Entry.model_validate({
                "dn": dn,
                "attributes": attrs,
            })
            normalized_result = quirk.normalize_entry_to_rfc(raw_entry)

            if normalized_result.is_success:
                entries.append(normalized_result.unwrap())
        return FlextResult.ok(entries)

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
            # 1. If server_type is explicitly provided, validate and use it
            if server_type is not None:
                quirks = self._quirk_registry.get_quirks(server_type)
                if not quirks:
                    return FlextResult.fail(
                        f"No quirk implementation found for explicitly specified server type '{server_type}'. "
                        f"Please ensure the server type is registered in the quirks registry."
                    )
                return FlextResult.ok(server_type)

            # 2. Check configuration-based resolution
            config = self._config

            # Relaxed mode takes precedence
            if config.enable_relaxed_parsing:
                return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

            # Manual mode uses specified server type
            if config.quirks_detection_mode == "manual":
                if config.quirks_server_type:
                    return FlextResult.ok(config.quirks_server_type)
                return FlextResult.fail(
                    "Manual mode requires quirks_server_type to be set in configuration"
                )

            # Auto-detection mode
            if config.quirks_detection_mode == "auto":
                if ldif_path or ldif_content:
                    detection_result = self._server_detector.detect_server_type(
                        ldif_path=ldif_path, ldif_content=ldif_content
                    )
                    if detection_result.is_success:
                        detected_data = detection_result.unwrap()
                        detected_type = detected_data.detected_server_type
                        if detected_type:
                            self._logger.info(
                                f"Auto-detected server type: {detected_type}"
                            )
                            return FlextResult.ok(detected_type)

                # Auto-detection failed or no content provided - use RELAXED as last resort
                self._logger.warning(
                    "Auto-detection failed or no content provided, using RELAXED mode"
                )
                return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

            # Disabled mode or fallback to default server type
            default_type = getattr(
                config,
                "ldif_default_server_type",
                FlextLdifConstants.ServerTypes.RELAXED,
            )
            return FlextResult.ok(default_type)

        except (ValueError, TypeError, AttributeError) as e:
            # Last resort fallback - use RELAXED mode
            self._logger.exception(f"Error resolving server type: {e}")
            return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

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
                processed_entry = entry

                # 1. Normalize DNs if requested
                if options.normalize_dns:
                    processed_entry = self._normalize_entry_dn(processed_entry)

                # 2. Schema processing
                if options.auto_parse_schema and self._is_schema_entry(processed_entry):
                    schema_count += 1
                    processed_entry = self._parse_schema_entry(
                        processed_entry, server_type
                    )
                else:
                    data_count += 1

                # 3. ACL extraction
                if options.auto_extract_acls:
                    processed_entry = self._extract_acls(processed_entry, server_type)

                # 4. Entry validation
                if options.validate_entries:
                    validation_result = self._validate_entry(
                        processed_entry, options.strict_schema_validation
                    )
                    if validation_result.is_failure:
                        if options.strict_schema_validation:
                            # In strict mode, raise exception to stop processing
                            msg = f"Strict validation failed for entry {processed_entry.dn}: {validation_result.error}"
                            raise ValueError(msg)
                        # In non-strict mode, log warning and continue
                        self._logger.warning(
                            f"Entry validation warning for {processed_entry.dn}: {validation_result.error}"
                        )
                        validation_errors.append(validation_result.error)

                # 5. Operational attributes handling
                if not options.include_operational_attrs:
                    processed_entry = self._filter_operational_attributes(
                        processed_entry
                    )

                processed_entries.append(processed_entry)

            except Exception as e:
                parse_errors += 1
                error_msg = f"Error processing entry {entry.dn if hasattr(entry, 'dn') else 'unknown'}: {e}"
                self._logger.exception(error_msg)

                # Check if we've hit the max error limit
                if (
                    options.max_parse_errors > 0
                    and parse_errors >= options.max_parse_errors
                ):
                    self._logger.exception(
                        f"Maximum parse errors ({options.max_parse_errors}) reached, stopping processing"
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
        self, entry: FlextLdifModels.Entry
    ) -> FlextLdifModels.Entry:
        """Normalize DN formatting to RFC 2253 standard."""
        try:
            # Basic normalization - remove extra spaces, standardize case for keywords
            dn_str = str(entry.dn.value)
            # This is a simplified normalization - in production you'd use a proper DN parser
            normalized_str = dn_str.strip()
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
        self, entry: FlextLdifModels.Entry, strict: bool = False
    ) -> FlextResult[bool]:
        """Validate entry against LDAP schema rules."""
        try:
            # Basic entry validation
            validation_errors = []

            # 1. Check DN is not empty
            if not entry.dn or not entry.dn.value:
                validation_errors.append("Entry DN cannot be empty")

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
                    attr_value.values, list
                ):
                    values = attr_value.values
                else:
                    values = [attr_value]

                if not values or all(not v for v in values):
                    if strict:
                        validation_errors.append(
                            f"Attribute '{attr_name}' has empty values"
                        )

            if validation_errors:
                return FlextResult.fail("; ".join(validation_errors))

            return FlextResult.ok(True)

        except Exception as e:
            return FlextResult.fail(f"Validation error: {e}")

    def _filter_operational_attributes(
        self, entry: FlextLdifModels.Entry
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
                f"Failed to filter operational attributes for entry {entry.dn}: {e}"
            )
            return entry

    # ==================== AUTOMATIC INTERNAL METHODS ====================

    def _is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema subentry (AUTOMATIC detection).

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema subentry, False otherwise

        """
        dn_lower = str(entry.dn).lower()

        # Check DN patterns using constants
        schema_dn_patterns = [
            FlextLdifConstants.DnPatterns.CN_SCHEMA.lower(),
            FlextLdifConstants.DnPatterns.CN_SUBSCHEMA.lower(),
        ]
        if any(pattern in dn_lower for pattern in schema_dn_patterns):
            return True

        # Check objectClass
        object_classes = entry.attributes.get("objectClass", [])
        if object_classes and any(
            oc.lower() in {"subschema", "subentry"} for oc in object_classes
        ):
            return True

        # Check for schema attributes
        has_attr_types = (
            FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES in entry.attributes
        )
        has_obj_classes = (
            FlextLdifConstants.SchemaFields.OBJECT_CLASSES in entry.attributes
        )

        return has_attr_types or has_obj_classes

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
            schema_quirks = self._quirk_registry.get_schema_quirks(server_type)
            if not schema_quirks:
                schema_quirks = self._quirk_registry.get_schema_quirks(
                    FlextLdifConstants.ServerTypes.RFC,
                )

            schema_attributes = []
            schema_objectclasses = []

            # Parse attributeTypes with SCHEMA QUIRKS
            attr_types = entry.attributes.get(
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES, []
            )
            if attr_types:
                for attr_def in attr_types:
                    for quirk in schema_quirks:
                        # Create a dummy SchemaAttribute to satisfy the protocol
                        dummy_attribute = (
                            FlextLdifModels.SchemaAttribute.model_validate({
                                "raw": attr_def
                            })
                        )
                        if quirk.can_handle_attribute(dummy_attribute):
                            result = quirk.parse_attribute(attr_def)
                            if result.is_success:
                                schema_attributes.append(result.unwrap())
                                break

            # Parse objectClasses with SCHEMA QUIRKS
            obj_classes = entry.attributes.get(
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES, []
            )
            if obj_classes:
                for oc_def in obj_classes:
                    for quirk in schema_quirks:
                        dummy_objectclass = (
                            FlextLdifModels.SchemaObjectClass.model_validate({
                                "raw": oc_def
                            })
                        )
                        if quirk.can_handle_objectclass(dummy_objectclass):
                            oc_result = quirk.parse_objectclass(oc_def)
                            if oc_result.is_success:
                                schema_objectclasses.append(oc_result.unwrap())
                                break

            # Store in Entry fields
            return entry.model_copy(
                update={
                    "attributes_schema": (schema_attributes or None),
                    "objectclasses": (schema_objectclasses or None),
                }
            )

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self._logger.warning(f"Error parsing schema entry: {e}")
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
                entry, server_type=server_type
            )

            if acl_result.is_success and acl_result.value:
                # Extract just the acls list from AclResponse
                acl_response = acl_result.value
                if acl_response.acls:
                    return entry.model_copy(update={"acls": acl_response.acls})

            return entry

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self._logger.warning(f"Error extracting ACLs: {e}")
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


__all__ = ["FlextLdifParserService"]
