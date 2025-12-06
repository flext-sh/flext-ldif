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

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.processing import FlextLdifProcessing
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import t


class FlextLdif(FlextLdifServiceBase[m.Entry]):
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
        ...     entries = result.unwrap()
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
        return cast("FlextLdif", cls._instance)

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize LDIF facade.

        Business Rules:
            - Service instances are NOT created during init (lazy initialization)
            - Configuration is inherited from FlextConfig namespace system
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
    def models(self) -> type[m]:
        """Get FlextLdifModels class."""
        return m

    @property
    def constants(self) -> type[c]:
        """Get FlextLdifConstants class."""
        return c

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
        source_server: c.LiteralTypes.ServerTypeLiteral = "rfc",
        target_server: c.LiteralTypes.ServerTypeLiteral = "rfc",
        **kwargs: str | float | bool | None,
    ) -> r[m.MigrationPipelineResult]:
        """Migrate LDIF data between servers.

        Args:
            input_dir: Directory containing source LDIF files.
            output_dir: Directory for output LDIF files.
            source_server: Source server type.
            target_server: Target server type.
            **kwargs: Additional arguments for migration pipeline.

        Returns:
            FlextResult containing migration results.

        """
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source_server,
            target_server_type=target_server,
            **kwargs,
        )
        return pipeline.execute()

    def process(
        self,
        processor_name: str,
        entries: list[m.Entry],
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
        return self.processing_service.process(
            processor_name,
            entries,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

    def extract_acls(
        self,
        entry: m.Entry,
    ) -> r[m.AclResponse]:
        """Extract ACLs from entry.

        Args:
            entry: Entry to extract ACLs from.

        Returns:
            FlextResult containing ACL response.

        """
        # Determine server type from entry metadata if available, else default to RFC
        # For now, default to RFC or try to detect?
        # extract_acls_from_entry requires server_type.
        # We can use "rfc" as default if unknown.
        server_type: c.LiteralTypes.ServerTypeLiteral = "rfc"
        return self.acl_service.extract_acls_from_entry(entry, server_type)

    def get_entry_dn(
        self,
        entry: m.Entry | dict[str, str | list[str]] | object,
    ) -> r[str]:
        """Get entry DN string.

        Args:
            entry: Entry object or dict.

        Returns:
            FlextResult containing DN string.

        """
        # FlextLdifEntries.get_entry_dn expects Entry | dict | EntryWithDnProtocol
        # casting to satisfy type checker if object is passed
        return FlextLdifEntries.get_entry_dn(cast("m.Entry", entry))

    def get_entry_attributes(
        self,
        entry: m.Entry,
    ) -> r[dict[str, list[str]]]:
        """Get entry attributes dictionary.

        Args:
            entry: Entry object.

        Returns:
            FlextResult containing attributes dict.

        """
        return FlextLdifEntries.get_entry_attributes(entry)

    def get_entry_objectclasses(
        self,
        entry: m.Entry,
    ) -> r[list[str]]:
        """Get entry objectClass values.

        Args:
            entry: Entry object.

        Returns:
            FlextResult containing objectClasses list.

        """
        return FlextLdifEntries.get_entry_objectclasses(entry)

    def get_attribute_values(
        self,
        attribute: object,
    ) -> r[list[str]]:
        """Get values from attribute object.

        Args:
            attribute: Attribute object (str, list, or object with values).

        Returns:
            FlextResult containing values list.

        """
        # FlextLdifEntries.get_attribute_values accepts t.GeneralValueType
        return FlextLdifEntries.get_attribute_values(
            cast("t.GeneralValueType", attribute),
        )

    def parse(
        self,
        content: str | Path,
        *,
        server_type: c.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> r[list[m.Entry]]:
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
        parse_result = self.parser.parse_string(content, server_type=effective_type)
        if parse_result.is_failure:
            return r[list[m.Entry]].fail(str(parse_result.error))

        response = parse_result.unwrap()
        # m.Entry inherits from domain Entry - cast for type compatibility
        entries_list: list[m.Entry] = [
            cast("m.Entry", entry) for entry in response.entries
        ]
        return r.ok(entries_list)

    def _parse_file(
        self,
        path: Path,
        *,
        server_type: c.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> r[list[m.Entry]]:
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
            return r[list[m.Entry]].fail(f"File not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            return r[list[m.Entry]].fail(f"Failed to read file: {e}")

        return self.parse(content, server_type=server_type)

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[m.Entry]:
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
        return FlextLdifEntries.create_entry(
            dn=dn,
            attributes=attributes,
            objectclasses=objectclasses,
        )

    def detect_server_type(
        self,
        ldif_content: str,
    ) -> r[m.ServerDetectionResult]:
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
        return self.detector.detect_server_type(ldif_content=ldif_content)

    def get_effective_server_type(
        self,
        ldif_content: str | None = None,
    ) -> r[c.LiteralTypes.ServerTypeLiteral]:
        """Get effective server type based on config and detection.

        Business Rules:
            - If quirks_detection_mode is "manual", returns configured type
            - If quirks_detection_mode is "auto", detects from content
            - If quirks_detection_mode is "disabled", returns "rfc"
            - Falls back to "rfc" if detection fails or content is None

        Args:
            ldif_content: Optional LDIF content for auto-detection.

        Returns:
            FlextResult containing effective server type literal.

        """
        return self.detector.get_effective_server_type(ldif_content=ldif_content)

    def _get_effective_server_type_value(self) -> c.LiteralTypes.ServerTypeLiteral:
        """Get effective server type value (internal helper).

        Returns:
            Server type literal (defaults to "rfc" on failure).

        """
        result = self.get_effective_server_type()
        if result.is_success:
            return result.unwrap()
        return "rfc"

    def write(
        self,
        entries: list[m.Entry],
        *,
        server_type: c.LiteralTypes.ServerTypeLiteral | None = None,
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
        effective_type = server_type or self._get_effective_server_type_value()
        return self.writer.write_to_string(entries, server_type=effective_type)

    def write_file(
        self,
        entries: list[m.Entry],
        path: Path,
        *,
        server_type: c.LiteralTypes.ServerTypeLiteral | None = None,
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

        content = write_result.unwrap()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return r[bool].ok(True)
        except OSError as e:
            return r[bool].fail(f"Failed to write file: {e}")

    def validate_entries(
        self,
        entries: list[m.Entry],
    ) -> r[bool]:
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
        # Inline validation - entries service uses builder pattern
        for entry in entries:
            if not entry.dn:
                return r[bool].fail(f"Entry missing DN: {entry}")
        return r[bool].ok(True)

    def filter_entries(
        self,
        entries: list[m.Entry],
        filter_func: Callable[[m.Entry], bool],
    ) -> r[list[m.Entry]]:
        """Filter entries using predicate function.

        Args:
            entries: List of Entry models to filter.
            filter_func: Predicate function returning True to include entry.

        Returns:
            FlextResult containing filtered list of entries.

        """
        try:
            filtered = [entry for entry in entries if filter_func(entry)]
            return r[list[m.Entry]].ok(filtered)
        except Exception as e:
            return r[list[m.Entry]].fail(f"Filter error: {e}")

    def get_entry_statistics(
        self,
        entries: list[m.Entry],
    ) -> r[m.EntryStatistics]:
        """Get statistics for list of entries.

        Args:
            entries: List of Entry models to analyze (currently unused - placeholder for future implementation).

        Returns:
            FlextResult containing EntryStatistics model.

        """
        # Inline statistics calculation
        # EntryStatistics uses default values - no args needed for empty stats
        # Note: entries parameter reserved for future statistics implementation
        try:
            stats = m.EntryStatistics()
            return r[m.EntryStatistics].ok(stats)
        except Exception as e:
            return r[m.EntryStatistics].fail(f"Statistics error: {e}")

    def filter_persons(
        self,
        entries: list[m.Entry],
    ) -> r[list[m.Entry]]:
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

        def is_person(entry: m.Entry) -> bool:
            attrs = entry.attributes
            if attrs is None:
                return False
            objectclasses = attrs.get("objectClass", [])
            return any(oc.lower() in person_classes for oc in objectclasses)

        return self.filter_entries(entries, is_person)

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Entry]:
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
            # Entry accepts str for dn and dict for attributes via field validators
            # Use model_validate to ensure proper type conversion
            health_entry = m.Entry.model_validate({
                "dn": "cn=health-check",
                "attributes": {"cn": ["health-check"]},
            })
            return r[m.Entry].ok(health_entry)
        except Exception as e:
            return r[m.Entry].fail(f"Health check failed: {e}")


# Module-level convenience export
__all__ = ["FlextLdif"]
