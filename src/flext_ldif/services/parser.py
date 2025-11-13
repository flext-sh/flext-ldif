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
from pathlib import Path
from typing import Any, cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifParser(FlextService[FlextLdifModels.ParseResponse]):
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

    # ==================== NESTED HELPER CLASSES ====================
    # These replace private methods with composable, testable classes

    class InputRouter:
        """Handles input routing and parsing - replaces _handle_input_routing and _parse_from_* methods."""

        def __init__(self, registry: FlextLdifServer, logger: FlextLogger) -> None:
            """Initialize with registry and logger."""
            self.registry = registry
            self.logger = logger

        def route_and_parse(
            self,
            input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
            content: str | Path | list[tuple[str, dict[str, list[str]]]],
            effective_type: str,
            encoding: str,
        ) -> FlextResult[FlextLdifModels.ParseResult]:
            """Route input to appropriate parser based on input source."""
            result: FlextResult[FlextLdifModels.ParseResult]

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
        ) -> FlextResult[FlextLdifModels.ParseResult]:
            """Parse LDIF from string content."""
            quirks = self.registry.get_entrys(server_type)
            if not quirks:
                return FlextResult.fail(
                    f"Internal error: No entry quirk found for resolved server type '{server_type}'",
                )

            entry = quirks[0]
            return cast(
                "FlextResult[FlextLdifModels.ParseResult]", entry.parse(content)
            )

        def parse_file(
            self,
            path: Path,
            encoding: str,
            server_type: str,
        ) -> FlextResult[FlextLdifModels.ParseResult]:
            """Parse LDIF from file."""
            if not path.exists():
                return FlextResult.fail(f"LDIF file not found: {path}")
            try:
                content = path.read_text(encoding=encoding)
                return self.parse_string(content, server_type)
            except (FileNotFoundError, OSError, Exception) as e:
                return FlextResult.fail(f"Failed to read LDIF file: {e}")

        def parse_ldap3(
            self,
            results: list[tuple[str, dict[str, list[str]]]],
            server_type: str,
        ) -> FlextResult[FlextLdifModels.ParseResult]:
            """Parse LDAP3 search results into Entry models."""
            quirks = self.registry.gets(server_type)
            if not quirks:
                return FlextResult.fail(
                    f"No quirk available for server type: {server_type}",
                )
            quirk = quirks[0]

            entries = []
            failed_count = 0
            failed_details: list[str] = []

            for dn, attrs in results:
                entry_result = quirk.entry_quirk.parse_entry(dn, attrs)

                if entry_result.is_success:
                    entries.append(entry_result.unwrap())
                else:
                    failed_count += 1
                    error_msg = f"DN: {dn}, Error: {entry_result.error}"
                    failed_details.append(error_msg)
                    self.logger.error(
                        f"FAILED to parse LDAP3 entry {dn}: {entry_result.error}",
                    )

            if failed_count > 0:
                self.logger.error(
                    f"LDAP3 parse completed with {failed_count} FAILURES out of {len(results)} total entries. "
                    f"Successful: {len(entries)}, Failed: {failed_count}",
                )

            return FlextResult.ok((entries, failed_count, failed_details))

    class ServerTypeResolver:
        """Handles server type resolution - replaces _resolve_server_type method."""

        def __init__(
            self,
            config: FlextLdifConfig,
            registry: FlextLdifServer,
            detector: FlextLdifDetector,
            logger: FlextLogger,
        ) -> None:
            """Initialize with config, registry, detector and logger."""
            self.config = config
            self.registry = registry
            self.detector = detector
            self.logger = logger

        def _validate_explicit_server_type(self, server_type: str) -> FlextResult[str]:
            """Validate explicitly specified server type."""
            quirks = self.registry.gets(server_type)
            if not quirks:
                return FlextResult.fail(
                    f"No quirk implementation found for server type '{server_type}'. "
                    "Ensure server type is registered in quirks registry."
                )
            return FlextResult.ok(server_type)

        def _try_auto_detect(
            self, ldif_path: Path | None, ldif_content: str | None
        ) -> FlextResult[str]:
            """Attempt auto-detection from LDIF content."""
            if not ldif_path and not ldif_content:
                return FlextResult.fail("No content for auto-detection")

            detection_result = self.detector.detect_server_type(
                ldif_path=ldif_path, ldif_content=ldif_content
            )
            if detection_result.is_failure:
                return FlextResult.fail("Auto-detection failed")

            detected_data = detection_result.unwrap()
            detected_type = detected_data.detected_server_type
            if not detected_type:
                return FlextResult.fail("No server type detected")

            self.logger.info("Auto-detected server type: %s", detected_type)
            return FlextResult.ok(detected_type)

        def resolve(
            self,
            server_type: str | None,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
        ) -> FlextResult[str]:
            """Resolve the effective server type based on configuration and auto-detection."""
            try:
                # Validate explicit server type if provided
                if server_type is not None:
                    return self._validate_explicit_server_type(server_type)

                config = self.config

                # Use structural pattern matching for server type resolution
                match config:
                    case FlextLdifConfig(enable_relaxed_parsing=True):
                        return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

                    case FlextLdifConfig(
                        quirks_detection_mode="manual",
                        quirks_server_type=str() as manual_type,
                    ):
                        return FlextResult.ok(manual_type)

                    case FlextLdifConfig(quirks_detection_mode="manual"):
                        return FlextResult.fail(
                            "Manual mode requires quirks_server_type in configuration"
                        )

                    case FlextLdifConfig(quirks_detection_mode="auto"):
                        # Try auto-detection
                        detect_result = self._try_auto_detect(ldif_path, ldif_content)
                        if detect_result.is_success:
                            return detect_result

                        self.logger.warning("Auto-detection failed, using RELAXED mode")
                        return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

                # Default fallback
                default = getattr(
                    config,
                    "ldif_default_server_type",
                    FlextLdifConstants.ServerTypes.RELAXED,
                )
                return FlextResult.ok(default)

            except (ValueError, TypeError, AttributeError):
                self.logger.exception("Error resolving server type")
                return FlextResult.ok(FlextLdifConstants.ServerTypes.RELAXED)

    class EntryProcessor:
        """Handles entry processing - replaces _process_single_entry, _post_process_entries, _normalize_entry_dn, _filter_operational_attributes."""

        def __init__(
            self,
            schema_extractor: FlextLdifParser.SchemaExtractor,
            acl_extractor: FlextLdifParser.AclExtractor,
            validator: FlextLdifParser.EntryValidator,
            logger: FlextLogger,
        ) -> None:
            """Initialize with schema extractor, ACL extractor, validator and logger."""
            self.schema_extractor = schema_extractor
            self.acl_extractor = acl_extractor
            self.validator = validator
            self.logger = logger

        def apply_schema_quirks_inline(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Apply schema quirks to inline schema attributes (CRITICAL for OID matching rule typos).

            Schema entries have attributes like:
            - attributetypes: [list of attribute definitions]
            - objectclasses: [list of objectclass definitions]

            These are LDIF entries, not parsed schema. We need to apply quirks normalization
            to the VALUES of these attributes to fix typos like:
            - EQUALITY caseIgnoreSubStringsMatch → SUBSTR caseIgnoreSubstringsMatch

            This is PHASE 7 fix for the 3 typos found in OID schema fixture.
            """
            if server_type != "oid":
                # Only apply to OID for now (other servers can be added later)
                return entry

            # Schema attribute names (case-insensitive)
            schema_attrs = {
                "attributetypes",
                "objectclasses",
                "matchingrules",
                "ldapsyntaxes",
            }

            # Check if entry has attributes and schema attributes
            if not entry.attributes:
                return entry

            has_schema = any(
                attr_name.lower() in schema_attrs
                for attr_name in entry.attributes.attributes
            )

            if not has_schema:
                return entry

            # Get server quirk from registry to access constants dynamically
            registry = FlextLdifServer.get_global_instance()
            server_quirk = registry.get_base(server_type)

            if server_quirk is None or not hasattr(server_quirk, "Constants"):
                # No quirk registered or no Constants class, return entry unchanged
                return entry

            # Access matching rule replacements from server quirk constants
            replacements = getattr(
                server_quirk.Constants,
                "MATCHING_RULE_TO_RFC",
                {}
            )

            # Create new attributes dict with normalized values
            new_attributes = {}
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name.lower() not in schema_attrs:
                    # Not a schema attribute, keep as-is
                    new_attributes[attr_name] = attr_values
                    continue

                # Normalize each value by applying matching rule replacements
                normalized_values = []
                for value in attr_values:
                    normalized_value = value
                    for typo, correct in replacements.items():
                        # Replace typos in the schema definition string
                        normalized_value = normalized_value.replace(typo, correct)
                    normalized_values.append(normalized_value)

                new_attributes[attr_name] = normalized_values

            # Create new entry with normalized attributes
            return FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=FlextLdifModels.LdifAttributes(attributes=new_attributes),
            )

        def process_single_entry(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
            options: FlextLdifModels.ParseFormatOptions,
        ) -> tuple[FlextLdifModels.Entry, int, int, list[str]]:
            """Process single entry with all transformations."""
            processed_entry = entry
            schema_count = 0
            data_count = 0
            validation_errors = []

            if options.normalize_dns:
                processed_entry = self.normalize_entry_dn(processed_entry)

            # PHASE 7 FIX: Apply schema quirks normalization to inline schema attributes
            # This fixes OID matching rule typos in attributetypes/objectclasses values
            processed_entry = self.apply_schema_quirks_inline(
                processed_entry, server_type
            )

            if options.auto_parse_schema and FlextLdifUtilities.Entry.is_schema_entry(
                processed_entry, strict=False
            ):
                schema_count = 1
                processed_entry = self.schema_extractor.parse_schema_entry(
                    processed_entry, server_type
                )
            else:
                data_count = 1

            if options.auto_extract_acls:
                processed_entry = self.acl_extractor.extract_acls(
                    processed_entry, server_type
                )

            if options.validate_entries:
                validation_result = self.validator.validate_entry(
                    processed_entry,
                    strict=options.strict_schema_validation,
                )
                if validation_result.is_failure:
                    # Get readable DN value for logging
                    dn_value = (
                        processed_entry.dn.value if processed_entry.dn else "unknown"
                    )
                    if options.strict_schema_validation:
                        msg = f"Strict validation failed for entry {dn_value}: {validation_result.error}"
                        raise ValueError(msg)
                    # Use structured logging to avoid base64 encoding
                    self.logger.warning(
                        "Entry validation warning",
                        dn=dn_value,
                        error=validation_result.error,
                    )
                    validation_errors.append(validation_result.error)

            if not options.include_operational_attrs:
                processed_entry = self.filter_operational_attributes(processed_entry)

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
                    error_msg = f"Error processing entry {entry.dn if hasattr(entry, 'dn') else 'unknown'}: {e}"
                    self.logger.exception(error_msg)

                    if (
                        options.max_parse_errors > 0
                        and parse_errors >= options.max_parse_errors
                    ):
                        self.logger.exception(
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

        def normalize_entry_dn(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize DN formatting to RFC 4514 standard."""
            try:
                if not entry.dn:
                    return entry
                dn_str = str(entry.dn.value)
                normalized_str = FlextLdifUtilities.DN.norm(dn_str)

                if normalized_str is None:
                    normalized_str = FlextLdifUtilities.DN.clean_dn(dn_str)

                normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_str)
                entry_dict = entry.model_dump()
                entry_dict["dn"] = normalized_dn
                return FlextLdifModels.Entry.model_validate(entry_dict)
            except Exception as e:
                self.logger.warning(f"Failed to normalize DN for entry {entry.dn}: {e}")
                return entry

        def filter_operational_attributes(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Filter out operational attributes from entry."""
            try:
                # Check if entry has attributes
                if not entry.attributes:
                    return entry

                is_schema_entry = FlextLdifUtilities.Entry.is_schema_entry(
                    entry, strict=False
                )

                operational_attrs = {
                    attr.lower()
                    for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_ALL_ENTRIES
                }

                if not is_schema_entry:
                    schema_operational_attrs = {
                        attr.lower()
                        for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_NON_SCHEMA_ENTRIES
                    }
                    operational_attrs.update(schema_operational_attrs)

                filtered_attrs = {
                    attr_name: attr_value
                    for attr_name, attr_value in entry.attributes.attributes.items()
                    if attr_name.lower() not in operational_attrs
                }

                new_attributes = FlextLdifModels.LdifAttributes(
                    attributes=filtered_attrs,
                    attribute_metadata=entry.attributes.attribute_metadata,
                    metadata=entry.attributes.metadata,
                )

                return entry.model_copy(update={"attributes": new_attributes})

            except Exception as e:
                self.logger.warning(
                    f"Failed to filter operational attributes for entry {entry.dn}: {e}",
                )
                return entry

    class EntryValidator:
        """Handles entry validation - replaces _validate_entry and _validate_entry_* methods."""

        def __init__(self, logger: FlextLogger) -> None:
            """Initialize with logger."""
            self.logger = logger

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
                    entry, strict=strict, errors=validation_errors
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

    class SchemaExtractor:
        """Handles schema extraction - replaces _parse_attribute_types_from_entry, _parse_objectclasses_from_entry, _parse_schema_entry."""

        def __init__(self, registry: FlextLdifServer, logger: FlextLogger) -> None:
            """Initialize with registry and logger."""
            self.registry = registry
            self.logger = logger

        def parse_schema_entry(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str,
        ) -> FlextLdifModels.Entry:
            """Parse schema entry attributes into models."""
            try:
                schemas = self.registry.gets(server_type)
                if not schemas:
                    schemas = self.registry.gets(
                        FlextLdifConstants.ServerTypes.RFC,
                    )

                schema_attributes = self.parse_attribute_types(entry, schemas)
                schema_objectclasses = self.parse_objectclasses(entry, schemas)

                return entry.model_copy(
                    update={
                        "attributes_schema": (schema_attributes or None),
                        "objectclasses": (schema_objectclasses or None),
                    },
                )

            except (ValueError, TypeError, AttributeError, Exception) as e:
                self.logger.warning("Error parsing schema entry: %s", e)
                return entry

        def parse_attribute_types(
            self,
            entry: FlextLdifModels.Entry,
            schemas: list[Any]
        ) -> list[FlextLdifModels.SchemaAttribute]:
            """Parse attributeTypes from entry using schema quirks."""
            schema_attributes: list[FlextLdifModels.SchemaAttribute] = []
            if not entry.attributes:
                return schema_attributes

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

        def parse_objectclasses(
            self,
            entry: FlextLdifModels.Entry,
            schemas: list[Any]
        ) -> list[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClasses from entry using schema quirks."""
            schema_objectclasses: list[FlextLdifModels.SchemaObjectClass] = []
            if not entry.attributes:
                return schema_objectclasses

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

    class AclExtractor:
        """Handles ACL extraction - replaces _extract_acls method."""

        def __init__(self, acl_service: FlextLdifAcl, logger: FlextLogger) -> None:
            """Initialize with ACL service and logger."""
            self.acl_service = acl_service
            self.logger = logger

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
                        return entry.model_copy(update={"acls": acl_response.acls})

                return entry

            except (ValueError, TypeError, AttributeError, Exception) as e:
                self.logger.warning("Error extracting ACLs: %s", e)
                return entry

    class StatisticsBuilder:
        """Handles statistics finalization - replaces _finalize_statistics method."""

        def __init__(self, *, enable_events: bool, logger: FlextLogger) -> None:
            """Initialize with event enablement flag and logger."""
            self.enable_events = enable_events
            self.logger = logger

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
                stats = stats.model_copy(
                    update={"parse_errors": stats.parse_errors + failed_count},
                )
                self.logger.error(
                    f"Parse completed with {failed_count} entry failures. "
                    f"See details in parse_errors field. Failed entries: {failed_details[:5]}"
                )

            # Emit ParseEvent if enabled
            if self.enable_events:
                # Calculate schema entries count (for future use in events)
                sum(
                    1
                    for entry in processed_entries
                    if "cn=schema" in str(entry.dn).lower()
                )

                if input_source == "file" and isinstance(content, Path):
                    parse_event = FlextLdifModels.ParseEvent.for_file(
                        file_path=content,
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=cast(
                            "list[object] | None",
                            failed_details if failed_count > 0 else None,
                        ),
                    )
                elif input_source == "ldap3":
                    parse_event = FlextLdifModels.ParseEvent.for_ldap3(
                        connection_info=f"ldap3_{effective_type}",
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=cast(
                            "list[object] | None",
                            failed_details if failed_count > 0 else None,
                        ),
                    )
                else:  # string
                    parse_event = FlextLdifModels.ParseEvent.for_string(
                        content_length=len(content) if isinstance(content, str) else 0,
                        entries_parsed=len(processed_entries),
                        parse_duration_ms=parse_duration_ms,
                        error_details=cast(
                            "list[object] | None",
                            failed_details if failed_count > 0 else None,
                        ),
                    )

                stats = cast("FlextLdifModels.Statistics", stats.add_event(parse_event))

            return stats

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

            return FlextResult.ok(response)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
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
        """Unified method to parse LDIF content from various sources using nested helper classes."""
        start_time = time.perf_counter()

        try:
            options = format_options or FlextLdifModels.ParseFormatOptions()

            # Initialize nested helpers
            router = self.InputRouter(self._registry, self._logger)
            resolver = self.ServerTypeResolver(
                self._config, self._registry, self._detector, self._logger
            )
            validator = self.EntryValidator(self._logger)
            schema_extractor = self.SchemaExtractor(self._registry, self._logger)
            acl_extractor = self.AclExtractor(self._acl_service, self._logger)
            processor = self.EntryProcessor(
                schema_extractor, acl_extractor, validator, self._logger
            )
            stats_builder = self.StatisticsBuilder(
                enable_events=self._enable_events, logger=self._logger
            )

            # Resolve effective server type
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

            server_type_result = resolver.resolve(
                server_type=server_type,
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
            if server_type_result.is_failure:
                return FlextResult.fail(
                    f"Server type resolution failed: {server_type_result.error}",
                )

            effective_type = server_type_result.unwrap()

            # Route to appropriate parser
            entries_result = router.route_and_parse(
                input_source, content, effective_type, encoding
            )
            if entries_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse LDIF content: {entries_result.error}",
                )

            # Extract results - inline (handles both list and tuple returns from ldap3)
            entries_data = entries_result.unwrap()
            if input_source == "ldap3" and isinstance(entries_data, tuple):
                entries, failed_count, failed_details = entries_data
            else:
                entries = cast("list[FlextLdifModels.Entry]", entries_data)
                failed_count, failed_details = 0, []

            # Post-process entries
            processed_entries, stats = processor.post_process_entries(
                entries, effective_type, options
            )

            # Calculate parse duration and finalize statistics
            parse_duration_ms = (time.perf_counter() - start_time) * 1000.0
            stats = stats_builder.finalize(
                stats,
                failed_count,
                failed_details,
                processed_entries,
                parse_duration_ms,
                input_source,
                content,
                effective_type,
            )

            # Create ParseResponse with entries and statistics
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
