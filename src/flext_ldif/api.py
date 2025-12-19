"""FLEXT-LDIF API - Unified Facade for LDIF Operations.

This module provides the primary entry point for all LDIF operations in the FLEXT
ecosystem. The FlextLdif class serves as a facade for LDIF parsing, writing,
validation, and server detection operations.

Business Rules:
    - All LDIF operations MUST flow through this facade (single entry point pattern)
    - Service instances are created lazily on first use (performance optimization)
    - FlextResult pattern is used for all operations (no exceptions raised)
    - Server type detection supports auto/manual/disabled modes via config

Audit Implications:
    - All operations are logged via FlextLdifServiceBase.logger
    - Parse/write operations create audit trail with entry counts
    - Detection operations log confidence scores and detected types
    - Error messages include operation context for forensic analysis

Architecture Notes:
    - Implements Facade pattern over service classes (Parser, Writer, Detector)
    - Uses Singleton pattern for global instance access
    - Context manager support for resource cleanup
    - All services inherit from FlextLdifServiceBase for consistent config access

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, cast, override

from flext_core import r
from pydantic import BaseModel

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.analysis import FlextLdifAnalysis
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.processing import FlextLdifProcessing
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import t


class FlextLdif(FlextLdifServiceBase[object]):
    r"""Main API facade for LDIF operations using composition pattern.

    Provides a unified interface for LDIF parsing, writing, validation, and
    server type detection. All operations return FlextResult for consistent
    error handling.

    Business Rules:
        - Single entry point for all LDIF operations (facade pattern)
        - Lazy initialization of service instances for performance
        - Server type can be auto-detected or explicitly configured
        - All parse/write operations support server-specific quirks

    Audit Implications:
        - Facade initialization logged at INFO level
        - All operations inherit logging from service base class
        - Entry counts and statistics logged for compliance reporting
        - Detection confidence scores logged for traceability

    Architecture Notes:
        - Implements FlextService pattern via ``FlextLdifServiceBase[Entry]``
        - Uses dict for service caching (Pydantic-compatible)
        - Singleton pattern via get_instance() for global access
        - Context manager support for resource cleanup

    Example:
        >>> from flext_ldif import FlextLdif
        >>> api = FlextLdif()
        >>> result = api.parse("dn: cn=test\ncn: test\n\n")
        >>> if result.is_success:
        ...     entries = result.value
        ...     print(f"Parsed {len(entries)} entries")

    """

    _instance: ClassVar[FlextLdif | None] = None

    @classmethod
    def get_instance(cls) -> FlextLdif:
        """Get singleton instance of FlextLdif.

        Business Rules:
             - Returns existing instance if available
             - Creates new instance if none exists
             - Thread-safe initialization (implied by GIL for simple assignment)

        Returns:
            Singleton instance of FlextLdif facade.

        """
        if cls._instance is None:
            cls._instance = cls()
        # Type narrowing: after None check, _instance is FlextLdif
        return cls._instance

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize LDIF facade.

        Business Rules:
            - Service instances are NOT created during init (lazy initialization)
            - Configuration is inherited from FlextSettings namespace system
            - Initialization is logged at INFO level for audit trail

        Audit Implications:
            - Facade initialization logged with readiness flags
            - No actual LDIF operations performed during init

        Args:
            **kwargs: Additional kwargs for FlextService base class.

        """
        super().__init__(**kwargs)
        # Store services in model_extra dict to avoid frozen issues
        self.__dict__["_service_cache"] = {}
        self.logger.info("FlextLdif facade initialized")

    def _get_service_cache(self) -> dict[str, object]:
        """Get service cache dict."""
        cache = self.__dict__.get("_service_cache")
        if cache is None:
            cache = {}
            self.__dict__["_service_cache"] = cache
        return cache

    @property
    def processing_service(self) -> FlextLdifProcessing:
        """Get processing service instance (lazy initialization).

        Returns:
            FlextLdifProcessing instance for batch/parallel processing.

        """
        cache = self._get_service_cache()
        if "processing_service" not in cache:
            cache["processing_service"] = FlextLdifProcessing()
        svc = cache["processing_service"]
        if not isinstance(svc, FlextLdifProcessing):
            svc = FlextLdifProcessing()
            cache["processing_service"] = svc
        return svc

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Get ACL service instance (lazy initialization).

        Returns:
            FlextLdifAcl instance for ACL operations.

        """
        cache = self._get_service_cache()
        if "acl_service" not in cache:
            cache["acl_service"] = FlextLdifAcl(server=self.server)
        svc = cache["acl_service"]
        if not isinstance(svc, FlextLdifAcl):
            svc = FlextLdifAcl(server=self.server)
            cache["acl_service"] = svc
        return svc

    @property
    def models(self) -> type[FlextLdifModelsDomains]:
        """Get FlextLdifModelsDomains class."""
        return FlextLdifModelsDomains

    @property
    def constants(self) -> type[object]:
        """Get constants (use string literals instead)."""
        return type[object]

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser service instance (lazy initialization).

        Returns:
            FlextLdifParser instance for LDIF parsing operations.

        """
        cache = self._get_service_cache()
        if "parser" not in cache:
            cache["parser"] = FlextLdifParser(server=self.server)
        parser = cache["parser"]
        if not isinstance(parser, FlextLdifParser):
            parser = FlextLdifParser(server=self.server)
            cache["parser"] = parser
        return parser

    @property
    def writer(self) -> FlextLdifWriter:
        """Get writer service instance (lazy initialization).

        Returns:
            FlextLdifWriter instance for LDIF writing operations.

        """
        cache = self._get_service_cache()
        if "writer" not in cache:
            cache["writer"] = FlextLdifWriter()
        writer = cache["writer"]
        if not isinstance(writer, FlextLdifWriter):
            writer = FlextLdifWriter()
            cache["writer"] = writer
        return writer

    @property
    def detector(self) -> FlextLdifDetector:
        """Get detector service instance (lazy initialization).

        Returns:
            FlextLdifDetector instance for server type detection.

        """
        cache = self._get_service_cache()
        if "detector" not in cache:
            cache["detector"] = FlextLdifDetector()
        detector = cache["detector"]
        if not isinstance(detector, FlextLdifDetector):
            detector = FlextLdifDetector()
            cache["detector"] = detector
        return detector

    @property
    def entries_service(self) -> FlextLdifEntries:
        """Get entries service instance (lazy initialization).

        Returns:
            FlextLdifEntries instance for entry operations.

        """
        cache = self._get_service_cache()
        if "entries_service" not in cache:
            cache["entries_service"] = FlextLdifEntries()
        entries_svc = cache["entries_service"]
        if not isinstance(entries_svc, FlextLdifEntries):
            entries_svc = FlextLdifEntries()
            cache["entries_service"] = entries_svc
        return entries_svc

    @property
    def server(self) -> FlextLdifServer:
        """Get server registry instance (lazy initialization).

        Returns:
            FlextLdifServer instance for server-specific quirks.

        """
        cache = self._get_service_cache()
        if "server" not in cache:
            cache["server"] = FlextLdifServer()
        server = cache["server"]
        if not isinstance(server, FlextLdifServer):
            server = FlextLdifServer()
            cache["server"] = server
        return server

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = "rfc",
        target_server: str = "rfc",
        options: m.Ldif.MigrateOptions | None = None,
        **kwargs: str | float | bool | None,
    ) -> r[m.Ldif.LdifResults.MigrationPipelineResult]:
        """Migrate LDIF data between servers.

        Args:
            input_dir: Directory containing source LDIF files.
            output_dir: Directory for output LDIF files.
            source_server: Source server type.
            target_server: Target server type.
            options: Migration options (MigrateOptions model).
            **kwargs: Additional arguments for migration pipeline (will be merged with options).

        Returns:
            FlextResult containing migration results.

        """
        # Merge options into kwargs if provided
        if options and hasattr(options, "write_options") and options.write_options:
            kwargs.setdefault("fold_long_lines", options.write_options.fold_long_lines)
            kwargs.setdefault("sort_attributes", options.write_options.sort_attributes)
            # Add other MigrateOptions fields to kwargs as needed
        # Type narrowing: str to ServerTypeLiteral (cast is safe as API validates server types)
        source_server_typed: str = str(source_server)
        target_server_typed: str = str(target_server)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source_server_typed,
            target_server_type=target_server_typed,
            **kwargs,
        )
        return pipeline.execute()

    def process(
        self,
        processor_name: str,
        entries: list[object],  # Lazy import: m.Ldif.Entry
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> r[list]:
        """Process entries using processing service.

        Args:
            processor_name: Name of processor ("transform", "validate").
            entries: List of entries to process.
            parallel: Whether to use parallel processing.
            batch_size: Batch size for sequential processing.
            max_workers: Max workers for parallel processing.

        Returns:
            FlextResult containing processed results.

        """
        # Type narrowing: entries is list[object], convert to list[m.Ldif.Entry]
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                # Already the correct type, use directly
                entries_typed.append(entry)
            elif isinstance(entry, BaseModel):
                # Other Pydantic model, use JSON mode to exclude computed properties
                entry_json = entry.model_dump_json()
                entries_typed.append(m.Ldif.Entry.model_validate_json(entry_json))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
        result = self.processing_service.process(
            processor_name,
            entries_typed,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )
        return cast("r[list]", result)

    def extract_acls(
        self,
        entry: object,
    ) -> r[object]:
        """Extract ACLs from entry.

        Args:
            entry: Entry to extract ACLs from.

        Returns:
            FlextResult containing ACL response.

        """
        # Determine server type from entry metadata if available, else default to RFC
        server_type: str = "rfc"
        # Type narrowing: entry is object, convert to m.Ldif.Entry
        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            # Other Pydantic model, use JSON mode to exclude computed properties
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        result = self.acl_service.extract_acls_from_entry(
            entry_typed,
            server_type,
        )
        return cast("r[object]", result)

    def get_entry_dn(
        self,
        entry: object,
    ) -> r[str]:
        """Get entry DN string.

        Args:
            entry: Entry object or dict.

        Returns:
            FlextResult containing DN string.

        """
        return FlextLdifEntries.get_entry_dn(entry)

    def get_entry_attributes(
        self,
        entry: object,  # Lazy import: m.Ldif.Entry
    ) -> r[dict[str, list[str]]]:
        """Get entry attributes dictionary.

        Args:
            entry: Entry object.

        Returns:
            FlextResult containing attributes dict.

        """
        # Type narrowing: entry is object, convert to m.Ldif.Entry
        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_attributes(entry_typed)

    def get_entry_objectclasses(
        self,
        entry: object,  # Lazy import: m.Ldif.Entry
    ) -> r[list[str]]:
        """Get entry objectClass values.

        Args:
            entry: Entry object.

        Returns:
            FlextResult containing objectClasses list.

        """
        # Type narrowing: entry is object, convert to m.Ldif.Entry
        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_objectclasses(entry_typed)

    def get_attribute_values(
        self,
        attribute: t.GeneralValueType,
    ) -> r[list[str]]:
        """Get values from attribute object.

        Args:
            attribute: Attribute object (str, list, or object with values).

        Returns:
            FlextResult containing values list.

        """
        return FlextLdifEntries.get_attribute_values(attribute)

    def parse(
        self,
        content: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[list[object]]:
        """Parse LDIF content from string or file.

        Business Rules:
            - Accepts both string content and file paths
            - Server type can be specified or auto-detected
            - Returns list of Entry models with parsed attributes
            - Empty content returns empty list (not an error)

        Audit Implications:
            - Parse operations logged with entry counts
            - Server type used for parsing logged for traceability
            - Errors include content snippet for debugging

        Args:
            content: LDIF content as string or Path to file.
            server_type: Optional server type for quirks (auto-detected if None).

        Returns:
            FlextResult containing list of parsed Entry models.

        """
        # Determine effective server type
        effective_type = server_type or self._get_effective_server_type_value()

        # Handle file path input
        if isinstance(content, Path):
            return self._parse_file(content, server_type=effective_type)

        # Parse string content
        parse_result = self.parser.parse_string(
            content,
            server_type=effective_type,
        )
        if parse_result.is_failure:
            return r[list[object]].fail(str(parse_result.error))

        response = parse_result.value
        entries_list: list[object] = list(response.entries)
        return r.ok(entries_list)

    def _parse_file(
        self,
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[list[object]]:
        """Parse LDIF file (internal helper).

        Business Rules:
            - File must exist and be readable
            - Large files loaded into memory (streaming not yet supported)
            - Server type can be specified or auto-detected

        Args:
            path: Path to LDIF file.
            server_type: Optional server type for quirks.

        Returns:
            FlextResult containing list of parsed Entry models.

        """
        if not path.exists():
            return r[list[object]].fail(f"File not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            return r[list[object]].fail(f"Failed to read file: {e}")

        return self.parse(content, server_type=server_type)

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[object]:
        """Create a new Entry model.

        Business Rules:
            - DN is required and must be valid
            - Attributes must be dict[str, str | list[str]] format
            - Entry is validated during creation

        Args:
            dn: Distinguished name for the entry.
            attributes: Entry attributes as dict of attribute name to values.
            objectclasses: Optional list of objectClasses to add.

        Returns:
            FlextResult containing created Entry model.

        """
        result = FlextLdifEntries.create_entry(
            dn=dn,
            attributes=attributes,
            objectclasses=objectclasses,
        )
        return cast("r[object]", result)

    def detect_server_type(
        self,
        ldif_content: str | Path,
    ) -> r[m.Ldif.LdifResults.ServerDetectionResult]:
        """Detect LDAP server type from LDIF content.

        Business Rules:
            - Analyzes content for server-specific patterns
            - Returns detection result with confidence score
            - Falls back to RFC if no patterns detected
            - Minimum confidence threshold: 0.6

        Audit Implications:
            - Detection results logged with confidence scores
            - Pattern matches logged for traceability

        Args:
            ldif_content: LDIF content to analyze.

        Returns:
            FlextResult containing ServerDetectionResult with server type and confidence.

        """
        # Convert Path to str if needed
        content_str: str | None = None
        if isinstance(ldif_content, Path):
            try:
                content_str = ldif_content.read_text(encoding="utf-8")
            except OSError as e:
                return r[object].fail(f"Failed to read file: {e}")
        else:
            content_str = ldif_content
        return self.detector.detect_server_type(ldif_content=content_str)

    def get_effective_server_type(
        self,
        ldif_content: str | None = None,
    ) -> r[str]:
        """Get effective server type based on config and detection.

        Business Rules:
            - If quirks_detection_mode is "manual", returns configured type
            - If quirks_detection_mode is "auto", detects from content
            - If quirks_detection_mode is "disabled", returns "rfc"
            - Falls back to "rfc" if detection fails or content is None

        Args:
            ldif_content: Optional LDIF content for auto-detection.

        Returns:
            FlextResult containing effective server type string.

        """
        return self.detector.get_effective_server_type(ldif_content=ldif_content)

    def _get_effective_server_type_value(self) -> str:
        """Get effective server type value (internal helper).

        Returns:
            Server type string (defaults to "rfc" on failure).

        """
        result = self.get_effective_server_type()
        if result.is_success:
            return result.value
        return "rfc"

    def write(
        self,
        entries: list[object],
        *,
        server_type: str | None = None,
    ) -> r[str]:
        """Write entries to LDIF format string.

        Business Rules:
            - Produces RFC 2849 compliant LDIF output
            - Server type controls formatting quirks
            - Empty entry list produces empty string

        Args:
            entries: List of Entry models to write.
            server_type: Optional server type for formatting quirks.

        Returns:
            FlextResult containing LDIF formatted string.

        """
        # Type narrowing: entries is list[object], convert to list[m.Ldif.Entry]
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, BaseModel):
                entry_json = entry.model_dump_json()
                entries_typed.append(m.Ldif.Entry.model_validate_json(entry_json))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
        # Type narrowing: server_type str to ServerTypeLiteral
        effective_type = server_type or self._get_effective_server_type_value()
        server_type_typed: str | None = (
            str(effective_type) if effective_type is not None else None
        )
        return self.writer.write_to_string(
            entries_typed,
            server_type=server_type_typed,
        )

    def write_file(
        self,
        entries: list[object],
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[bool]:
        """Write entries to LDIF file.

        Business Rules:
            - Creates parent directories if needed
            - Overwrites existing file
            - Uses UTF-8 encoding

        Args:
            entries: List of Entry models to write.
            path: Output file path.
            server_type: Optional server type for formatting quirks.

        Returns:
            FlextResult containing True on success.

        """
        write_result = self.write(entries, server_type=server_type)
        if write_result.is_failure:
            return r[bool].fail(str(write_result.error))

        content = write_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return r[bool].ok(True)
        except OSError as e:
            return r[bool].fail(f"Failed to write file: {e}")

    def validate_entries(
        self,
        entries: list[object],
    ) -> r[object]:
        """Validate list of entries.

        Business Rules:
            - Validates DN format for each entry
            - Validates required attributes present
            - Returns True if all entries valid

        Args:
            entries: List of Entry models to validate.

        Returns:
            FlextResult containing True if all valid, error message otherwise.

        """
        # Type narrowing: entries is list[object], convert to list[m.Ldif.Entry]
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, dict):
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
        # Use validation service for proper ValidationResult
        validation_service = FlextLdifValidation()
        result = FlextLdifAnalysis.validate_entries(
            entries_typed,
            validation_service,
        )
        return cast("r[object]", result)

    def filter_entries(
        self,
        entries: list[object],
        filter_func: Callable[[object], bool],
    ) -> r[list[object]]:
        """Filter entries using predicate function.

        Args:
            entries: List of Entry models to filter.
            filter_func: Predicate function returning True to include entry.

        Returns:
            FlextResult containing filtered list of entries.

        """
        try:
            filtered = [entry for entry in entries if filter_func(entry)]
            return r[list[object]].ok(filtered)
        except Exception as e:
            return r[list[object]].fail(f"Filter error: {e}")

    def get_entry_statistics(
        self,
        _entries: list[object],
    ) -> r[object]:
        """Get statistics for list of entries.

        Args:
            _entries: List of Entry models to analyze.

        Returns:
            FlextResult containing EntriesStatistics model.

        """
        # Type narrowing: entries is list[object], convert to list[m.Ldif.Entry]
        entries_typed: list[m.Ldif.Entry] = []
        for entry in _entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, dict):
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
        # Use statistics service instead of direct model access
        stats_service = FlextLdifStatistics()
        return cast("r[object]", stats_service.calculate_for_entries(entries_typed))

    def filter_persons(
        self,
        entries: list[object],
    ) -> r[list[object]]:
        """Filter entries to only person entries.

        Business Rules:
            - Filters by objectClass containing "person", "inetOrgPerson",
              "organizationalPerson", or similar person object classes.

        Args:
            entries: List of Entry models to filter.

        Returns:
            FlextResult containing filtered list of person entries.

        """
        person_classes = {"person", "inetorgperson", "organizationalperson"}

        def is_person(entry: object) -> bool:
            # Use hasattr check for structural typing (protocol compliance)
            if not hasattr(entry, "attributes") or not hasattr(entry, "dn"):
                return False
            attrs = getattr(entry, "attributes")
            if attrs is None:
                return False
            # Handle both dict-like and model-like attributes
            if isinstance(attrs, dict) or hasattr(attrs, "get"):
                objectclasses = attrs.get("objectClass", [])
            else:
                return False
            if isinstance(objectclasses, str):
                objectclasses = [objectclasses]
            return any(oc.lower() in person_classes for oc in objectclasses)

        return self.filter_entries(entries, is_person)

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[object]:
        """Execute service health check for FlextService pattern compliance.

        Business Rules:
            - Returns success if facade is properly initialized
            - Used by service orchestrators for readiness checks

        Returns:
            FlextResult indicating service health.

        """
        # Health check - verify services can be accessed
        try:
            _ = self.parser
            _ = self.writer
            _ = self.detector
            # Use domain model directly
            health_entry = m.Ldif.Entry.model_validate({
                "dn": "cn=health-check",
                "attributes": {"cn": ["health-check"]},
            })
            return r[object].ok(health_entry)
        except Exception as e:
            return r[object].fail(f"Health check failed: {e}")


# Module-level convenience export
__all__ = ["FlextLdif"]
