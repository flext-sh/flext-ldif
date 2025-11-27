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
from pathlib import Path
from typing import override

from flext_core import FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.schema import FlextLdifSchema
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifParser(FlextLdifServiceBase[FlextLdifModels.ParseResponse]):
    r"""LDIF parsing service - PARSING ONLY with SRP-compliant architecture.

    PARSING MONOPOLY: All operations are parsing-related. File I/O, writing, and
    migration are delegated to dedicated services.

    Public Methods (PARSING ONLY):
        - parse(content, server_type): Parse LDIF content string
        - parse_file(path, server_type): Parse LDIF file
        - parse_ldap3_result(results, server_type): Parse LDAP search results

    Automatic Internal Processing:
        - Schema entry detection → automatic schema parsing via FlextLdifSchema
        - ACL attribute detection → automatic ACL extraction via FlextLdifAcl
        - Entry validation → via FlextLdifValidation
        - All via FlextLdifServer quirks for server-specific decoding

    NOT IN THIS SERVICE (delegated to other services):
        - Writing: Use FlextLdifWriter
        - Migration: Use FlextLdifMigrationPipeline
        - Server detection: Use FlextLdifDetector (used internally)

    Architecture:
        - Uses FlextLdifServer for ALL server-specific operations
          (no direct OID/OUD/RFC knowledge)
        - Uses FlextLdifAcl service for ACL extraction
        - Uses FlextLdifSchema service for schema parsing
        - Uses FlextLdifValidation service for entry validation
        - Uses FlextLdifUtilities for operations that don't require server differences
        - Returns FlextResult[ParseResponse] - always consistent type
        - Type-safe with Python 3.13+ annotations
        - Dependency injection pattern for all services

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
    _schema_service: FlextLdifSchema
    _validation_service: FlextLdifValidation
    _entry_service: FlextLdifEntries

    def __init__(
        self,
        *,
        enable_events: bool = False,
        registry: FlextLdifServer | None = None,
        acl_service: FlextLdifAcl | None = None,
        detector: FlextLdifDetector | None = None,
        schema_service: FlextLdifSchema | None = None,
        validation_service: FlextLdifValidation | None = None,
        entry_service: FlextLdifEntries | None = None,
    ) -> None:
        """Initialize parser service with dependency injection.

        Args:
            enable_events: Enable domain event emission
                (default: False for backward compatibility).
            registry: FlextLdifServer instance
                (default: creates new instance).
            acl_service: FlextLdifAcl instance
                (default: creates new instance).
            detector: FlextLdifDetector instance
                (default: creates new instance).
            schema_service: FlextLdifSchema instance
                (default: creates new instance).
            validation_service: FlextLdifValidation instance
                (default: creates new instance).

        Initializes:
            - FlextLdifServer: For all parsing modes (RFC/server-specific/relaxed)
            - FlextLdifAcl: For ACL extraction
            - FlextLdifDetector: For server type detection
            - FlextLdifSchema: For schema parsing
            - FlextLdifValidation: For entry validation

        Config is accessed via self.config.ldif (inherited from FlextLdifServiceBase).

        """
        super().__init__()
        self._enable_events = enable_events

        # Initialize parsing components with dependency injection
        self._registry = registry if registry is not None else FlextLdifServer()
        self._acl_service = acl_service if acl_service is not None else FlextLdifAcl()
        self._detector = detector if detector is not None else FlextLdifDetector()
        self._schema_service = (
            schema_service if schema_service is not None else FlextLdifSchema()
        )
        self._validation_service = (
            validation_service
            if validation_service is not None
            else FlextLdifValidation()
        )
        self._entry_service = (
            entry_service if entry_service is not None else FlextLdifEntries()
        )

    # ==================== PRIVATE PARSING METHODS ====================
    # These methods use services directly instead of nested classes

    def _route_and_parse(
        self,
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
        effective_type: str,
        encoding: str,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Route input to appropriate parser based on input source."""
        match (input_source, content):
            case ("string", str() as content_str):
                return self._parse_string(content_str, effective_type)
            case ("file", Path() as content_path):
                return self._parse_file(content_path, encoding, effective_type)
            case ("ldap3", list() as ldap3_content):
                return self._parse_ldap3(ldap3_content, effective_type)
            case ("ldap3", _):
                return FlextResult.fail("ldap3 input source requires list content")
            case _:
                return FlextResult.fail(f"Unsupported input source: {input_source}")

    def _parse_string(
        self,
        content: str,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF from string content using FlextLdifServer."""
        quirk_result = self._registry.quirk(server_type)
        if not quirk_result.is_success:
            self.logger.error(
                "Quirk not found",
                server_type=server_type,
                available_servers=self._registry.list_registered_servers(),
                error=quirk_result.error,
            )
            return FlextResult.fail(
                f"Internal error: No quirk found for resolved "
                f"server type '{server_type}': {quirk_result.error}",
            )

        quirk = quirk_result.unwrap()
        result = quirk.parse(content)

        if result.is_success:
            parse_response = result.unwrap()

            entries_with_original = sum(
                1
                for entry in parse_response.entries
                if isinstance(entry, FlextLdifModels.Entry)
                and entry.metadata is not None
                and entry.metadata.original_strings is not None
                and "entry_original_ldif" in entry.metadata.original_strings
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
                    missing_count=len(parse_response.entries) - entries_with_original,
                )
        else:
            self.logger.error(
                "Failed to parse LDIF string",
                server_type=server_type,
                error=str(result.error),
            )

        return result

    def _parse_file(
        self,
        path: Path,
        encoding: str,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF from file using FlextLdifServer."""
        if not path.exists():
            self.logger.error(
                "LDIF file not found",
                file_path=str(path),
            )
            return FlextResult.fail(f"LDIF file not found: {path}")

        try:
            content = path.read_text(encoding=encoding)
            return self._parse_string(content, server_type)
        except (FileNotFoundError, OSError, Exception) as e:
            self.logger.exception(
                "Failed to read LDIF file",
                file_path=str(path),
                encoding=encoding,
                error=str(e),
            )
            return FlextResult.fail(f"Failed to read LDIF file: {e}")

    def _parse_ldap3(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDAP3 search results into Entry models using FlextLdifServer."""
        quirk_result = self._registry.quirk(server_type)
        if not quirk_result.is_success:
            self.logger.error(
                "Quirk not found for LDAP3 parsing",
                server_type=server_type,
                error=quirk_result.error,
            )
            return FlextResult.fail(
                f"No quirk available for server type: {server_type}: {quirk_result.error}",
            )

        quirk = quirk_result.unwrap()

        entries: list[FlextLdifModels.Entry] = []
        failed_count = 0

        for idx, (dn, attrs) in enumerate(results):
            original_ldif_lines = [f"dn: {dn}"]
            original_ldif_lines.extend(
                f"{attr_name}: {value}"
                for attr_name, attr_values in attrs.items()
                for value in attr_values
            )
            original_ldif_content = "\n".join(original_ldif_lines) + "\n"

            entry_quirk = quirk.entry_quirk
            entry_result = entry_quirk.parse_entry(dn, attrs)

            if entry_result.is_success:
                entry = entry_result.unwrap()
                if entry.metadata:
                    FlextLdifUtilities.Metadata.preserve_original_ldif_content(
                        metadata=entry.metadata,
                        ldif_content=original_ldif_content,
                        context="entry_original_ldif",
                    )

                entries.append(entry)
            else:
                failed_count += 1
                self.logger.error(
                    "LDAP3 entry conversion failed",
                    entry_dn=dn,
                    entry_index=idx + 1,
                    error=str(entry_result.error)[:200],
                )

        stats = FlextLdifModels.Statistics(
            total_entries=len(results),
            processed_entries=len(entries),
            failed_entries=failed_count,
            parse_errors=failed_count,
            detected_server_type=server_type,
        )

        self.logger.info(
            "Parsed LDAP3 results",
            server_type=server_type,
            total_entries=len(results),
            successful_entries=len(entries),
            failed_entries=failed_count,
        )

        response = FlextLdifModels.ParseResponse(
            entries=list(entries),
            statistics=stats,
            detected_server_type=server_type,
        )
        return FlextResult[FlextLdifModels.ParseResponse].ok(response)

    def _apply_schema_quirks_inline(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Apply schema quirks to inline schema attributes via quirk delegation."""
        quirk_result = self._registry.quirk(server_type)
        if not quirk_result.is_success:
            return entry

        quirk = quirk_result.unwrap()

        entry_quirk = quirk.entry_quirk
        normalize_method = getattr(entry_quirk, "normalize_schema_strings_inline", None)
        if normalize_method:
            result = normalize_method(entry)
            if isinstance(result, FlextLdifModels.Entry):
                return result
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

        dn_before = str(entry.dn) if entry.dn else None
        normalized_entry = self._normalize_entry_dn(entry, server_type)
        dn_after = str(normalized_entry.dn) if normalized_entry.dn else None

        if (
            normalized_entry.metadata
            and dn_before
            and dn_after
            and dn_before != dn_after
        ):
            FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                metadata=normalized_entry.metadata,
                original=dn_before,
                converted=dn_after,
                context="dn_normalization",
                attribute_name="dn",
            )
        return normalized_entry

    def _normalize_entry_dn(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Normalize DN formatting via quirk delegation."""
        quirk_result = self._registry.quirk(server_type)
        if not quirk_result.is_success:
            return entry

        quirk = quirk_result.unwrap()

        entry_quirk = quirk.entry_quirk
        normalize_method = getattr(entry_quirk, "normalize_entry_dn", None)
        if normalize_method:
            try:
                result = normalize_method(entry)
                if isinstance(result, FlextLdifModels.Entry):
                    return result
            except Exception as e:
                self.logger.warning(
                    "Failed to normalize entry DN",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    error=str(e),
                )
        return entry

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
            parsed_entry = self._parse_schema_entry(entry, server_type)
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

        validation_result = self._validate_entry(entry, strict=strict)
        if validation_result.is_failure:
            dn_value = entry.dn.value if entry.dn else "unknown"
            if strict:
                msg = (
                    f"Strict validation failed for entry {dn_value}: "
                    f"{validation_result.error}"
                )
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
            error_msg = validation_result.error or "Entry validation failed"
            return [error_msg]
        return []

    def _filter_operational_attrs_if_needed(
        self,
        entry: FlextLdifModels.Entry,
        *,
        include_operational: bool,
    ) -> FlextLdifModels.Entry:
        """Remove operational attributes using FlextLdifEntries service."""
        if include_operational:
            return entry

        remove_result = self._entry_service.remove_operational_attributes_single(entry)
        if remove_result.is_success:
            return remove_result.unwrap()
        return entry

    def _process_single_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
        options: FlextLdifModels.ParseFormatOptions,
    ) -> tuple[FlextLdifModels.Entry, int, int, list[str]]:
        """Process single entry with all transformations."""
        processed_entry = self._normalize_entry_dn_if_needed(
            entry,
            server_type,
            normalize=options.normalize_dns,
        )

        processed_entry = self._apply_schema_quirks_inline(
            processed_entry,
            server_type,
        )

        processed_entry, schema_count, data_count = self._parse_schema_if_needed(
            processed_entry,
            server_type,
            auto_parse=options.auto_parse_schema,
        )

        if options.auto_extract_acls:
            processed_entry = self._extract_acls(processed_entry, server_type)

        validation_errors = self._validate_entry_if_needed(
            processed_entry,
            validate=options.validate_entries,
            strict=options.strict_schema_validation,
        )

        processed_entry = self._filter_operational_attrs_if_needed(
            processed_entry,
            include_operational=options.include_operational_attrs,
        )

        filtered_errors = [e for e in validation_errors if e is not None]
        return processed_entry, schema_count, data_count, filtered_errors

    def _post_process_entries(
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
                    self._process_single_entry(entry, server_type, options)
                )
                schema_count += schema_inc
                data_count += data_inc
                validation_errors.extend(val_errs)
                processed_entries.append(processed_entry)

            except Exception as e:
                parse_errors += 1
                entry_dn_value = (
                    FlextLdifUtilities.DN.get_dn_value(entry.dn)
                    if entry.dn
                    else "unknown"
                )
                self.logger.exception(
                    "Failed to process entry",
                    entry_dn=entry_dn_value,
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

    def _validate_entry(
        self,
        entry: FlextLdifModels.Entry,
        *,
        strict: bool = False,
    ) -> FlextResult[bool]:
        """Validate entry using FlextLdifValidation service."""
        validation_errors: list[str] = []

        # Validate DN using utilities
        dn_str = str(entry.dn.value) if entry.dn else None
        if not dn_str:
            validation_errors.append("Entry DN cannot be empty")
        else:
            dn_validation = FlextLdifUtilities.DN.validate(dn_str)
            if not dn_validation:
                validation_errors.append(f"Invalid DN format: {dn_str}")

        # Validate objectClass using utilities
        if not entry.attributes:
            if strict:
                validation_errors.append("Entry must have objectClass attribute")
        else:
            has_objectclass = any(
                attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower()
                for attr_name in entry.attributes.attributes
            )
            if not has_objectclass and strict:
                validation_errors.append("Entry must have objectClass attribute")

        # Validate attribute values
        if entry.attributes:
            for attr_name, attr_value in entry.attributes.attributes.items():
                values: list[str] = list(attr_value) if attr_value else []
                if (not values or all(not v for v in values)) and strict:
                    validation_errors.append(
                        f"Attribute '{attr_name}' has empty values"
                    )

        if validation_errors:
            return FlextResult.fail("; ".join(validation_errors))

        return FlextResult.ok(True)

    def _parse_schema_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Parse schema entry using FlextLdifServer quirks and FlextLdifSchema service.

        Uses FlextLdifServer quirks for server-specific schema parsing.
        """
        try:
            quirk_result = self._registry.quirk(server_type)
            if not quirk_result.is_success or not entry.attributes:
                if not quirk_result.is_success:
                    self.logger.warning(
                        "Quirk not found for schema parsing",
                        server_type=server_type,
                        entry_dn=str(entry.dn) if entry.dn else None,
                        error=quirk_result.error,
                    )
                return entry

            quirk = quirk_result.unwrap()

            schema_quirk = quirk.schema_quirk
            schema_attributes = self._parse_schema_attributes(entry, schema_quirk)
            schema_objectclasses = self._parse_schema_objectclasses(entry, schema_quirk)

            self.logger.debug(
                "Parsed schema entry",
                entry_dn=str(entry.dn) if entry.dn else None,
                attributes_count=len(schema_attributes),
                objectclasses_count=len(schema_objectclasses),
                server_type=server_type,
            )

            return self._build_schema_entry_update(
                entry, schema_attributes, schema_objectclasses, server_type
            )

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self.logger.warning(
                "Failed to parse schema entry",
                entry_dn=str(entry.dn) if entry.dn else None,
                error=str(e),
            )
            return entry

    def _parse_schema_attributes(
        self,
        entry: FlextLdifModels.Entry,
        schema_quirk: object,
    ) -> list[FlextLdifModels.SchemaAttribute]:
        """Parse schema attributeTypes using quirk."""
        schema_attributes: list[FlextLdifModels.SchemaAttribute] = []
        attr_types = entry.attributes.get(
            FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
            [],
        )
        parse_method = getattr(schema_quirk, "parse_attribute", None)
        if parse_method:
            for definition in attr_types:
                parse_result = parse_method(definition)
                if parse_result.is_success:
                    schema_attributes.append(parse_result.unwrap())
        return schema_attributes

    def _parse_schema_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        schema_quirk: object,
    ) -> list[FlextLdifModels.SchemaObjectClass]:
        """Parse schema objectClasses using quirk."""
        schema_objectclasses: list[FlextLdifModels.SchemaObjectClass] = []
        obj_classes = entry.attributes.get(
            FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
            [],
        )
        parse_method = getattr(schema_quirk, "parse_objectclass", None)
        if parse_method:
            for definition in obj_classes:
                oc_parse_result = parse_method(definition)
                if oc_parse_result.is_success:
                    schema_objectclasses.append(oc_parse_result.unwrap())
        return schema_objectclasses

    def _build_schema_entry_update(
        self,
        entry: FlextLdifModels.Entry,
        schema_attributes: list[FlextLdifModels.SchemaAttribute],
        schema_objectclasses: list[FlextLdifModels.SchemaObjectClass],
        _server_type: str,
    ) -> FlextLdifModels.Entry:
        """Build schema entry update with metadata tracking."""
        update_dict: dict[str, object] = {}
        if schema_attributes:
            update_dict["attributes_schema"] = schema_attributes
        if schema_objectclasses:
            update_dict["objectclasses"] = schema_objectclasses

        parsed_entry = entry.model_copy(update=update_dict or None)

        # Track schema parsing in metadata using FlextLdifUtilities.Metadata
        if parsed_entry.metadata and (schema_attributes or schema_objectclasses):
            schema_count = len(schema_attributes) + len(schema_objectclasses)
            FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                metadata=parsed_entry.metadata,
                original=str(schema_count),
                converted=str(schema_count),
                context="schema_parsing",
                attribute_name=None,
            )

        return parsed_entry

    def _extract_acls(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextLdifModels.Entry:
        """Extract ACLs from entry using FlextLdifAcl service."""
        try:
            acl_result = self._acl_service.extract_acls_from_entry(
                entry,
                server_type=server_type,
            )

            if acl_result.is_success and acl_result.value:
                acl_response = acl_result.value
                if acl_response.acls:
                    # Ensure metadata exists using FlextLdifUtilities pattern
                    current_metadata = entry.metadata
                    if current_metadata is None:
                        current_metadata = FlextLdifModels.QuirkMetadata(
                            quirk_type=server_type,
                        )
                    new_metadata = current_metadata.model_copy(
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

    def _finalize_statistics(
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
        if failed_count > 0:
            stats = stats.model_copy(
                update={"parse_errors": stats.parse_errors + failed_count},
            )
            self.logger.error(
                "Parse completed with failures",
                failed_count=failed_count,
            )

        if self._enable_events:
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

            stats_result = stats.add_event(parse_event)
            if isinstance(stats_result, FlextLdifModels.Statistics):
                stats = stats_result
            else:
                msg = f"Expected Statistics, got {type(stats_result)}"
                raise TypeError(msg)

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

    def _resolve_server_type(
        self,
        server_type: str | None,
        content: str | Path | list[object],
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
    ) -> FlextResult[str]:
        """Resolve effective server type from explicit type or auto-detection."""
        if server_type is not None:
            quirk_result = self._registry.quirk(server_type)
            if quirk_result.is_failure:
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
        encoding: str = FlextLdifConstants.DEFAULT_ENCODING,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Unified method to parse LDIF content from various sources.

        Uses nested helper classes for routing and parsing.
        """
        start_time = time.perf_counter()
        self._log_parsing_start(
            content, input_source, server_type, encoding, format_options
        )

        try:
            options = self._prepare_format_options(format_options)
            self._initialize_helpers()
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
    ) -> None:
        """Initialize parser helpers (no longer needed - services are injected)."""
        self.logger.debug("Parser services initialized via dependency injection")

    def _normalize_content(
        self,
        content: str | Path | list[tuple[str, dict[str, list[str]]]],
    ) -> str | Path | list[tuple[str, dict[str, list[str]]]]:
        """Normalize content to typed format."""
        if isinstance(content, (str, Path)):
            return content
        if isinstance(content, list):
            return self._normalize_list_content(list(content))
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
        typed_content: str | Path | list[tuple[str, dict[str, list[str]]]],
        effective_type: str,
        encoding: str,
        input_source: FlextLdifConstants.LiteralTypes.ParserInputSource,
        options: FlextLdifModels.ParseFormatOptions,
        start_time: float,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Process parsed content and return response."""
        entries_result = self._route_and_parse(
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

        processed_entries, stats = self._post_process_entries(
            entries,
            effective_type,
            options,
        )

        parse_duration_ms = (time.perf_counter() - start_time) * 1000.0
        stats = self._finalize_statistics(
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
            entries=list(processed_entries),
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
        encoding: str = FlextLdifConstants.DEFAULT_ENCODING,
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
                encoding=getattr(
                    self.config.ldif,
                    "ldif_encoding",
                    FlextLdifConstants.DEFAULT_ENCODING,
                ),
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
            # Indicators: ends with .ldif, looks like absolute path,
            # or short string that exists as file
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
                    encoding=getattr(
                        self.config.ldif,
                        "ldif_encoding",
                        FlextLdifConstants.DEFAULT_ENCODING,
                    ),
                    format_options=format_options,
                )

            # Default: treat as LDIF content if ambiguous
            return self.parse_string(
                content=source,
                server_type=server_type,
                format_options=format_options,
            )

        source_type_name = type(source).__name__
        return FlextResult.fail(
            f"Source must be Path or str, got {source_type_name}",
        )


__all__ = ["FlextLdifParser"]
