"""Parser Service - Unified LDIF Parsing Operations with Nested Classes.

This service provides comprehensive LDIF parsing functionality including:
- RFC 2849 compliant entry parsing (via nested EntryParser)
- RFC 4512 compliant schema parsing (via nested SchemaParser)
- ACL parsing (via nested AclParser)
- RFC-compliant writing (via nested WriterService)
- Single and batch file parsing
- Pagination support for large files
- Schema LDIF parsing with modify operations
- Auto-detection of LDAP server types
- Relaxed parsing for non-compliant files
- Effective server type resolution
- Quirks support for RFC, server-specific, and relaxed modes

PARSING MONOPOLY: All parsing operations consolidated into self-contained
nested classes using quirks system for ALL modes (RFC, server-specific, relaxed).

Consolidates all parsing logic from separate RFC parsers into dedicated
nested classes following Single Responsibility Principle and FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.entry_quirks import FlextLdifEntrys
from flext_ldif.services.registry import FlextLdifRegistry

if TYPE_CHECKING:
    from flext_ldif.services.client import FlextLdifClient

# Python 3.13 compatibility: ldif3 uses deprecated base64.decodestring
if not hasattr(base64, "decodestring"):
    base64.decodestring = base64.decodebytes


class FlextLdifParserService(FlextService[dict[str, object]]):
    """Self-contained LDIF parsing service with nested parser classes.

    PARSING MONOPOLY: Consolidates all LDIF parsing operations into self-contained
    nested classes that use quirks system for RFC, server-specific, and relaxed modes.

    Nested Classes:
        - EntryParser: RFC 2849 compliant entry parsing with quirks support
        - SchemaParser: RFC 4512 compliant schema parsing with quirks support
        - AclParser: ACL parsing with server-specific quirks
        - WriterService: RFC-compliant entry/schema writing with quirks

    Public Methods:
        - parse(): Unified parsing (entry/batch/pagination) with quirks routing
        - parse_schema_ldif(): Schema LDIF with modify operations extraction
        - parse_with_auto_detection(): Automatic server type detection
        - parse_relaxed(): Lenient parsing for broken files
        - detect_server_type(): Manual server type detection
        - get_effective_server_type(): Server type resolution logic
        - write(): RFC-compliant writing with quirks support

    Architecture:
        - Self-contained with all parsing logic in nested classes
        - Uses FlextLdifRegistry for ALL modes (RFC/server-specific/relaxed)
        - Uses FlextLdifClient for I/O operations only (minimal dependency)
        - Returns FlextResult[T] for railway-oriented programming
        - Type-safe with Python 3.13+ annotations

    Example:
        >>> from flext_ldif.services.parser import FlextLdifParserService
        >>> from pathlib import Path
        >>>
        >>> # Initialize parser service
        >>> parser = FlextLdifParserService()
        >>>
        >>> # Parse single file (auto-detects quirks)
        >>> result = parser.parse(Path("data.ldif"))
        >>> if result.is_success:
        ...     entries = result.unwrap()
        >>>
        >>> # Parse with specific quirks
        >>> result = parser.parse(Path("oud.ldif"), server_type="oud")
        >>>
        >>> # Parse with pagination
        >>> result = parser.parse(Path("large.ldif"), paginate=True)

    """

    _client: FlextLdifClient | None  # Lazy-initialized
    _logger: FlextLogger
    _config: FlextLdifConfig
    _quirk_registry: FlextLdifRegistry
    _entry_quirks: FlextLdifEntrys
    _acl_service: FlextLdifAclService

    # Nested class: EntryParser (RFC 2849)
    class EntryParser:
        """RFC 2849 compliant LDIF entry parser with quirks support.

        Uses ldif3 library for RFC 2849 compliance with optional server-specific
        quirks enhancements and relaxed parsing for broken files.
        """

        def __init__(
            self,
            quirk_registry: FlextLdifRegistry,
            entry_quirks: FlextLdifEntrys,
            acl_service: FlextLdifAclService,
            logger: FlextLogger | None = None,
        ) -> None:
            """Initialize entry parser with quirks system."""
            self._quirk_registry = quirk_registry
            self._entry_quirks = entry_quirks
            self._acl_service = acl_service
            self._logger = logger

        def parse_content(
            self,
            content: str,
            server_type: str = FlextLdifConstants.ServerTypes.RFC,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content string with quirks support.

            Args:
                content: LDIF content as string
                server_type: Server type for quirk selection

            Returns:
                FlextResult with list of parsed entries

            """
            return self._parse_with_ldif3(content=content, server_type=server_type)

        def parse_file(
            self,
            path: str | Path,
            server_type: str = FlextLdifConstants.ServerTypes.RFC,
            encoding: str = FlextLdifConstants.Encoding.UTF8,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF file with quirks support.

            Args:
                path: Path to LDIF file
                server_type: Server type for quirk selection
                encoding: File encoding

            Returns:
                FlextResult with list of parsed entries

            """
            file_path = Path(path)
            return self._parse_with_ldif3(
                file_path=file_path,
                server_type=server_type,
                encoding=encoding,
            )

        def _parse_with_ldif3(
            self,
            content: str | None = None,
            file_path: Path | None = None,
            server_type: str = FlextLdifConstants.ServerTypes.RFC,
            encoding: str = FlextLdifConstants.Encoding.UTF8,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """ORCHESTRATOR: Coordinate parsing by delegating to quirks.

            Does NOT parse LDIF directly - quirks handle all ldif3 parsing.

            This method:
            1. Reads file content (if file_path provided)
            2. Gets entry quirk
            3. Delegates parsing to quirk.parse_content()
            4. Extracts ACLs from parsed entries
            5. Returns entries

            Args:
                content: LDIF content string (mutually exclusive with file_path)
                file_path: Path to LDIF file (mutually exclusive with content)
                server_type: Server type for quirk selection
                encoding: Character encoding (default: utf-8)

            Returns:
                FlextResult with list of parsed entries

            """
            try:
                # Step 1: Determine input source and read content
                ldif_content: str

                if content is not None:
                    ldif_content = content
                elif file_path is not None:
                    # Read file content
                    if not Path(file_path).exists():
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"LDIF file not found: {file_path}",
                        )
                    with Path(file_path).open("r", encoding=encoding) as f:
                        ldif_content = f.read()
                else:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        "Either content or file_path is required",
                    )

                # Step 2: Get entry quirk (will always be RFC as fallback)
                # First try to find a quirk for the requested server type
                quirk = self._quirk_registry.find_entry_quirk(
                    server_type=server_type,
                    entry_dn="",  # Don't need DN for quirk discovery
                    attributes={},  # Don't need attrs for quirk discovery
                )

                # If no quirk found, fallback to RFC baseline parser
                if not quirk:
                    # Try to get RFC quirk from registry as fallback
                    rfc_quirks = self._quirk_registry.get_entry_quirks(
                        FlextLdifConstants.ServerTypes.RFC,
                    )
                    if rfc_quirks:
                        quirk = rfc_quirks[0]
                    else:
                        # Last resort - instantiate RFC Entry quirk directly
                        from flext_ldif.servers.rfc import FlextLdifServersRfc

                        quirk = FlextLdifServersRfc.Entry()

                # At this point, quirk should never be None
                if not quirk:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Critical: No entry quirk available for server_type={server_type}",
                    )

                # Step 3: DELEGATE to quirk to parse LDIF content
                # Quirk internally uses ldif3 to iterate and parse all entries
                parse_result = quirk.parse_content(ldif_content)

                if not parse_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to parse LDIF: {parse_result.error}",
                    )

                entries = parse_result.unwrap()

                # Step 4: Extract ACLs from each parsed entry
                for i, entry in enumerate(entries):
                    acl_result = self._acl_service.extract_acls_from_entry(
                        entry,
                        server_type=server_type,
                    )
                    if acl_result.is_success:
                        acls = acl_result.value
                        if acls:
                            entries[i] = entry.model_copy(update={"acls": acls})

                # Step 5: Return parsed entries
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except (
                ValueError,
                TypeError,
                AttributeError,
                FileNotFoundError,
                OSError,
                Exception,
            ) as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse LDIF: {e}",
                )

    # Nested class: SchemaParser (RFC 4512)
    class SchemaParser:
        """RFC 4512 compliant LDAP schema parser with quirks support.

        Parses attribute types and objectClasses with optional server-specific quirks.
        """

        # RFC 4512: AttributeType definition regex
        ATTRIBUTE_TYPE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            (
                r"\(\s*"  # Opening parenthesis
                r"(?P<oid>[\d\.]+)\s+"  # OID (numeric)
                r"(?:NAME\s+'(?P<name>[^']+)'\s+)?"  # Optional NAME
                r"(?:DESC\s+'(?P<desc>[^']+)'\s+)?"  # Optional DESC
                r"(?:OBSOLETE\s+)?"  # Optional OBSOLETE
                r"(?:SUP\s+(?P<sup>\w+)\s+)?"  # Optional SUP
                r"(?:EQUALITY\s+(?P<equality>\w+)\s+)?"  # Optional EQUALITY
                r"(?:ORDERING\s+(?P<ordering>\w+)\s+)?"  # Optional ORDERING
                r"(?:SUBSTR\s+(?P<substr>\w+)\s+)?"  # Optional SUBSTR
                r"(?:SYNTAX\s+'(?P<syntax>[\d\.]+)'(?:\{(?P<length>\d+)\})?\s+)?"  # Optional SYNTAX
                r"(?:SINGLE-VALUE\s+)?"  # Optional SINGLE-VALUE
                r"(?:COLLECTIVE\s+)?"  # Optional COLLECTIVE
                r"(?:NO-USER-MODIFICATION\s+)?"  # Optional NO-USER-MODIFICATION
                r"(?:USAGE\s+(?P<usage>\w+)\s+)?"  # Optional USAGE
                r"\)"  # Closing parenthesis
            ),
            re.VERBOSE,
        )

        # RFC 4512: ObjectClass definition regex
        OBJECT_CLASS_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            (
                r"\(\s*"  # Opening parenthesis
                r"(?P<oid>[\d\.]+)\s+"  # OID (numeric)
                r"(?:NAME\s+'(?P<name>[^']+)'\s+)?"  # Optional NAME
                r"(?:DESC\s+'(?P<desc>[^']+)'\s+)?"  # Optional DESC
                r"(?:OBSOLETE\s+)?"  # Optional OBSOLETE
                r"(?:SUP\s+(?P<sup>[\w\$]+)\s+)?"  # Optional SUP
                r"(?:(?P<kind>STRUCTURAL|AUXILIARY|ABSTRACT)\s+)?"  # Optional kind
                r"(?:MUST\s+(?:\((?P<must_list>[^\)]+)\)|(?P<must_single>\w+))\s+)?"  # Optional MUST
                r"(?:MAY\s+(?:\((?P<may_list>[^\)]+)\)|(?P<may_single>\w+))\s+)?"  # Optional MAY
                r"\)"  # Closing parenthesis
            ),
            re.VERBOSE,
        )

        def __init__(
            self,
            quirk_registry: FlextLdifRegistry,
            logger: FlextLogger | None = None,
        ) -> None:
            """Initialize schema parser with quirks system."""
            self._quirk_registry = quirk_registry
            self._logger = logger

        def parse_file(
            self,
            path: str | Path,
            server_type: str | None = None,
            *,
            parse_attributes: bool = True,
            parse_objectclasses: bool = True,
        ) -> FlextResult[dict[str, object]]:
            """Parse schema file with quirks support.

            Args:
                path: Path to schema file
                server_type: Server type for quirk selection (optional)
                parse_attributes: Parse attributeTypes
                parse_objectclasses: Parse objectClasses

            Returns:
                FlextResult with parsed schema data

            """
            file_path = Path(path)
            if not file_path.exists():
                return FlextResult[dict[str, object]].fail(
                    f"Schema file not found: {file_path}",
                )

            return self._parse_schema_file(
                file_path,
                server_type=server_type,
                parse_attributes=parse_attributes,
                parse_objectclasses=parse_objectclasses,
            )

        def _parse_schema_file(
            self,
            file_path: Path,
            server_type: str | None = None,
            *,
            parse_attributes: bool = True,
            parse_objectclasses: bool = True,
        ) -> FlextResult[dict[str, object]]:
            """Parse schema file according to RFC 4512.

            Args:
                file_path: Path to schema LDIF file
                server_type: Optional server type for quirks
                parse_attributes: Parse attributeTypes
                parse_objectclasses: Parse objectClasses

            Returns:
                FlextResult with parsed schema data

            """
            try:
                attributes: dict[str, object] = {}
                objectclasses: dict[str, object] = {}
                source_dn = FlextLdifConstants.ServerDetection.SCHEMA_SUBENTRY_DN

                with file_path.open("r", encoding="utf-8") as f:
                    current_line = ""

                    for raw_line in f:
                        line = raw_line.rstrip("\n\r")

                        # Handle line folding (lines starting with space)
                        if line.startswith(" "):
                            current_line += " " + line[1:]
                            continue

                        # Process complete line
                        if current_line:
                            self._process_schema_line(
                                current_line,
                                attributes,
                                objectclasses,
                                server_type=server_type,
                                parse_attributes=parse_attributes,
                                parse_objectclasses=parse_objectclasses,
                            )

                        # Check for DN line (schema subentry)
                        if line.startswith("dn:"):
                            source_dn = line[3:].strip()

                        current_line = line

                    # Process last line
                    if current_line:
                        self._process_schema_line(
                            current_line,
                            attributes,
                            objectclasses,
                            server_type=server_type,
                            parse_attributes=parse_attributes,
                            parse_objectclasses=parse_objectclasses,
                        )

                return FlextResult[dict[str, object]].ok({
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attributes,
                    FlextLdifConstants.DictKeys.OBJECTCLASSES: objectclasses,
                    "source_dn": source_dn,
                    "stats": {
                        FlextLdifConstants.DictKeys.ATTRIBUTES_COUNT: len(attributes),
                        FlextLdifConstants.DictKeys.OBJECTCLASSES_COUNT: len(
                            objectclasses,
                        ),
                    },
                })

            except (ValueError, TypeError, AttributeError, OSError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to parse schema file: {e}",
                )

        def _process_schema_line(
            self,
            line: str,
            attributes: dict[str, object],
            objectclasses: dict[str, object],
            server_type: str | None = None,
            *,
            parse_attributes: bool = True,
            parse_objectclasses: bool = True,
        ) -> None:
            """Process a single schema line with quirks support.

            Args:
                line: Complete schema line (after folding)
                attributes: Dict to store parsed attributes
                objectclasses: Dict to store parsed objectClasses
                server_type: Server type for quirks
                parse_attributes: Parse attributeTypes
                parse_objectclasses: Parse objectClasses

            """
            try:
                # RFC 4512: AttributeType definition
                if parse_attributes and line.startswith(
                    FlextLdifConstants.ServerDetection.ATTRIBUTE_TYPES_PREFIX,
                ):
                    attr_def = line[
                        FlextLdifConstants.ServerDetection.ATTRIBUTE_TYPES_PREFIX_LENGTH :
                    ].strip()
                    attr_data = self._parse_attribute_type(attr_def, server_type)
                    if attr_data and "name" in attr_data:
                        attributes[str(attr_data["name"])] = attr_data

                # RFC 4512: ObjectClass definition
                elif parse_objectclasses and line.startswith(
                    FlextLdifConstants.ServerDetection.OBJECT_CLASSES_PREFIX,
                ):
                    oc_def = line[
                        FlextLdifConstants.ServerDetection.OBJECT_CLASSES_PREFIX_LENGTH :
                    ].strip()
                    oc_data = self._parse_object_class(oc_def, server_type)
                    if oc_data and "name" in oc_data:
                        objectclasses[str(oc_data["name"])] = oc_data

            except (ValueError, TypeError, AttributeError) as e:
                if self._logger is not None:
                    self._logger.warning(
                        "Error processing schema line: %s",
                        e,
                        extra={"line": line[:100]},
                    )

        def _parse_attribute_type(
            self,
            definition: str,
            server_type: str | None = None,
        ) -> dict[str, object] | None:
            """Parse RFC 4512 AttributeType definition with quirks support.

            Args:
                definition: AttributeType definition string
                server_type: Optional server type for quirks

            Returns:
                Dict with attribute metadata or None if parsing fails

            """
            # Try quirks first if available and server_type specified
            if self._quirk_registry and server_type:
                schema_quirks = self._quirk_registry.get_schema_quirks(server_type)
                for quirk in schema_quirks:
                    if quirk.can_handle_attribute(definition):
                        if self._logger:
                            self._logger.debug(
                                f"Using {quirk.server_type} quirk for attribute parsing",
                                extra={"definition": definition[:100]},
                            )
                        quirk_result = quirk.parse_attribute(definition)
                        if quirk_result.is_success:
                            # Quirks return models - convert to dict for compatibility
                            attr_model = quirk_result.unwrap()
                            return attr_model.model_dump(exclude_none=True)

            # Fall back to RFC 4512 standard parsing
            match = self.ATTRIBUTE_TYPE_PATTERN.match(definition)
            if not match:
                return None

            # Use Pydantic model internally for type safety and validation
            try:
                attribute_model = FlextLdifModels.SchemaAttribute(
                    oid=match.group("oid"),
                    name=match.group("name") or match.group("oid"),
                    desc=match.group("desc"),
                    sup=match.group("sup"),
                    equality=match.group("equality"),
                    ordering=match.group("ordering"),
                    substr=match.group("substr"),
                    syntax=match.group("syntax"),
                    length=(
                        int(match.group("length")) if match.group("length") else None
                    ),
                    usage=match.group("usage"),
                )

                # Convert model to dict for backward compatibility
                return attribute_model.model_dump(exclude_none=True)

            except (ValueError, TypeError, AttributeError) as e:
                if self._logger:
                    self._logger.warning(
                        "Failed to create SchemaAttribute model: %s",
                        e,
                        extra={"definition": definition[:100]},
                    )
                return None

        def _parse_object_class(
            self,
            definition: str,
            server_type: str | None = None,
        ) -> dict[str, object] | None:
            """Parse RFC 4512 ObjectClass definition with quirks support.

            Args:
                definition: ObjectClass definition string
                server_type: Optional server type for quirks

            Returns:
                Dict with objectClass metadata or None if parsing fails

            """
            # Try quirks first if available and server_type specified
            if self._quirk_registry and server_type:
                schema_quirks = self._quirk_registry.get_schema_quirks(server_type)
                for quirk in schema_quirks:
                    if quirk.can_handle_objectclass(definition):
                        if self._logger:
                            self._logger.debug(
                                f"Using {quirk.server_type} quirk for objectClass parsing",
                                extra={"definition": definition[:100]},
                            )
                        quirk_result = quirk.parse_objectclass(definition)
                        if quirk_result.is_success:
                            # Quirks return models - convert to dict for compatibility
                            oc_model = quirk_result.unwrap()
                            return oc_model.model_dump(exclude_none=True)

            # Fall back to RFC 4512 standard parsing
            match = self.OBJECT_CLASS_PATTERN.match(definition)
            if not match:
                return None

            # Parse MUST and MAY attribute lists
            must_attrs = []
            if match.group("must_list"):
                must_attrs = [
                    attr.strip()
                    for attr in match.group("must_list").split("$")
                    if attr.strip()
                ]
            elif match.group("must_single"):
                must_attrs = [match.group("must_single")]

            may_attrs = []
            if match.group("may_list"):
                may_attrs = [
                    attr.strip()
                    for attr in match.group("may_list").split("$")
                    if attr.strip()
                ]
            elif match.group("may_single"):
                may_attrs = [match.group("may_single")]

            # Use Pydantic model internally for type safety and validation
            try:
                objectclass_model = FlextLdifModels.SchemaObjectClass(
                    oid=match.group("oid"),
                    name=match.group("name") or match.group("oid"),
                    desc=match.group("desc"),
                    sup=match.group("sup"),
                    kind=match.group("kind") or "STRUCTURAL",
                    must=must_attrs,
                    may=may_attrs,
                )

                # Convert model to dict for backward compatibility
                return objectclass_model.model_dump(exclude_none=True)

            except (ValueError, TypeError, AttributeError) as e:
                if self._logger:
                    self._logger.warning(
                        "Failed to create SchemaObjectClass model: %s",
                        e,
                        extra={"definition": definition[:100]},
                    )
                return None

    # Nested class: AclParser
    class AclParser:
        """ACL parser with server-specific quirks support."""

        def __init__(
            self,
            acl_service: FlextLdifAclService,
            logger: FlextLogger | None = None,
        ) -> None:
            """Initialize ACL parser."""
            self._acl_service = acl_service
            self._logger = logger

        def extract_from_entry(
            self,
            entry: FlextLdifModels.Entry,
            server_type: str = FlextLdifConstants.ServerTypes.RFC,
        ) -> FlextResult[list[FlextLdifModels.Acl]]:
            """Extract ACLs from entry with quirks support.

            Args:
                entry: LDIF entry
                server_type: Server type for quirks

            Returns:
                FlextResult with list of extracted ACLs

            """
            return self._acl_service.extract_acls_from_entry(entry, server_type)

    def __init__(
        self,
        client: FlextLdifClient | None = None,
        config: FlextLdifConfig | None = None,
    ) -> None:
        """Initialize self-contained parser service with nested classes.

        Args:
            client: Optional FlextLdifClient instance (used for I/O only). If None, lazy-initialized.
            config: Optional FlextLdifConfig instance. If None, uses default config.

        Initializes:
            - FlextLdifRegistry: For all parsing modes (RFC/server-specific/relaxed)
            - EntryParser: Nested class for RFC 2849 entry parsing
            - SchemaParser: Nested class for RFC 4512 schema parsing
            - AclParser: Nested class for ACL parsing
            - FlextLdifClient: Minimal I/O operations only (lazy-initialized)

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._client = client  # Lazy-initialized only when needed for I/O
        self._logger = FlextLogger(__name__)

        # Initialize quirks system for ALL parsing modes
        self._quirk_registry = FlextLdifRegistry()
        self._entry_quirks = FlextLdifEntrys()
        self._acl_service = FlextLdifAclService()

    @property
    def _lazy_client(self) -> FlextLdifClient:  # type: ignore[name-defined]
        """Lazy-initialize client for I/O operations only.

        Returns:
            FlextLdifClient instance

        """
        if self._client is None:
            from flext_ldif.services.client import FlextLdifClient as _FlextLdifClient

            self._client = _FlextLdifClient(config=self._config)
        return self._client

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute parser service health check.

        Returns:
            FlextResult with service status dictionary containing:
            - service_name: "FlextLdifParserService"
            - status: "operational"
            - nested_classes: List of available nested parser classes

        """
        try:
            status: dict[str, object] = {
                "service_name": "FlextLdifParserService",
                "status": "operational",
                "nested_classes": [
                    "EntryParser (RFC 2849)",
                    "SchemaParser (RFC 4512)",
                    "AclParser (Server-specific)",
                ],
                "quirks_registry": "FlextLdifRegistry (RFC + server-specific + relaxed)",
            }

            return FlextResult[dict[str, object]].ok(status)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Parser service health check failed: {e}",
            )

    def parse(
        self,
        source: str | Path | list[str | Path],
        server_type: str = FlextLdifConstants.ServerTypes.RFC,
        *,
        batch: bool = False,
        paginate: bool = False,
        page_size: int = 1000,
    ) -> FlextResult[
        list[FlextLdifModels.Entry] | Callable[[], list[FlextLdifModels.Entry] | None]
    ]:
        r"""Unified parse method using nested EntryParser with quirks support.

        Self-contained parsing using nested EntryParser class that handles RFC 2849
        compliance with optional server-specific quirks and relaxed parsing modes.

        Args:
            source: Single source (str/Path/content) or list for batch processing.
            server_type: Server type for quirk selection ("rfc", "oid", "oud", "relaxed", etc.)
            batch: If True, parse list of sources. Default: False
            paginate: If True, return generator function. Default: False
            page_size: Number of entries per page when paginate=True. Default: 1000

        Returns:
            FlextResult containing:
            - list[Entry] when paginate=False
            - Callable[[], list[Entry] | None] when paginate=True

        Example:
            # Parse with nested EntryParser (self-contained)
            parser = FlextLdifParserService()
            result = parser.parse(Path("data.ldif"), server_type="oud")

        """
        # Initialize nested EntryParser
        entry_parser = self.EntryParser(
            self._quirk_registry,
            self._entry_quirks,
            self._acl_service,
            logger=self._logger,
        )

        # Helper method to check if source looks like a file path vs content
        def _is_likely_file_path(source_str: str) -> bool:
            r"""Heuristic to detect if string is likely a file path vs LDIF content.

            A string is likely a file path if:
            - It's not empty or whitespace-only
            - It's reasonably short (filesystem limit is typically 255 chars)
            - It ends with .ldif extension
            - It doesn't contain newlines (LDIF content contains \n)

            Args:
                source_str: The source string to check

            Returns:
                True if string looks like a file path, False if likely LDIF content

            """
            # Empty or whitespace-only strings are NOT file paths
            if not source_str or not source_str.strip():
                return False

            return len(source_str) < FlextLdifConstants.Format.MAX_FILENAME_LENGTH and (
                source_str.endswith(".ldif") or "\n" not in source_str
            )

        # Handle batch parsing
        if batch:
            if not isinstance(source, list):
                return FlextResult.fail(
                    "batch=True requires source to be a list of sources",
                )
            try:
                all_entries: list[FlextLdifModels.Entry] = []
                errors: list[str] = []

                for single_source in source:
                    # Parse single source using heuristic + safe Path check
                    source_str = str(single_source)
                    is_file = False

                    if isinstance(single_source, (str, Path)) and _is_likely_file_path(
                        source_str
                    ):
                        try:
                            # Safe check for file existence
                            if Path(source_str).exists():
                                is_file = True
                        except (OSError, ValueError):
                            # Path() creation failed - treat as content
                            is_file = False

                    if is_file:
                        result = entry_parser.parse_file(source_str, server_type)
                    else:
                        result = entry_parser.parse_content(source_str, server_type)

                    if result.is_success:
                        entries = result.unwrap()
                        all_entries.extend(entries)
                    else:
                        errors.append(
                            f"Failed to parse {single_source}: {result.error}",
                        )

                if errors and not all_entries:
                    return FlextResult[
                        list[FlextLdifModels.Entry]
                        | Callable[[], list[FlextLdifModels.Entry] | None]
                    ].fail(f"Batch parsing failed: {'; '.join(errors)}")

                if errors:
                    self._logger.warning(
                        f"Batch parsing completed with {len(errors)} error(s)",
                        extra={"errors": errors},
                    )

                return cast(
                    "FlextResult[list[FlextLdifModels.Entry] | Callable[[], list[FlextLdifModels.Entry] | None]]",
                    FlextResult[list[FlextLdifModels.Entry]].ok(all_entries),
                )

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[
                    list[FlextLdifModels.Entry]
                    | Callable[[], list[FlextLdifModels.Entry] | None]
                ].fail(f"Batch parsing failed: {e}")

        # Handle pagination
        if paginate:
            if isinstance(source, list):
                return FlextResult.fail(
                    "paginate=True requires single source, not list. Use batch=True.",
                )
            try:
                # Determine if source is file or content using heuristic + safe check
                source_str = str(source)
                is_file = False

                if isinstance(source, (str, Path)) and _is_likely_file_path(source_str):
                    try:
                        if Path(source_str).exists():
                            is_file = True
                    except (OSError, ValueError):
                        # Path() creation failed - treat as content
                        is_file = False

                if is_file:
                    parse_result = entry_parser.parse_file(source_str, server_type)
                else:
                    parse_result = entry_parser.parse_content(source_str, server_type)

                if parse_result.is_failure:
                    return FlextResult.fail(parse_result.error)

                all_entries = parse_result.unwrap()
                current_page_index = 0

                def get_next_page() -> list[FlextLdifModels.Entry] | None:
                    nonlocal current_page_index
                    start = current_page_index * page_size
                    end = start + page_size
                    current_page_index += 1

                    if start >= len(all_entries):
                        return None

                    return all_entries[start:end]

                return FlextResult[
                    list[FlextLdifModels.Entry]
                    | Callable[[], list[FlextLdifModels.Entry] | None]
                ].ok(get_next_page)

            except (ValueError, TypeError, AttributeError, OSError) as e:
                return FlextResult[
                    list[FlextLdifModels.Entry]
                    | Callable[[], list[FlextLdifModels.Entry] | None]
                ].fail(f"Pagination setup failed: {e}")

        # Handle single source parsing (default)
        if isinstance(source, list):
            return FlextResult[
                list[FlextLdifModels.Entry]
                | Callable[[], list[FlextLdifModels.Entry] | None]
            ].fail(
                "source is a list. Did you mean batch=True? Or provide a single source.",
            )

        # Parse single source using heuristic + safe Path check
        try:
            source_str = str(source)
            is_file = False

            if isinstance(source, (str, Path)) and _is_likely_file_path(source_str):
                try:
                    # Safe check for file existence
                    if Path(source_str).exists():
                        is_file = True
                except (OSError, ValueError):
                    # Path() creation failed - treat as content
                    is_file = False

            if is_file:
                # File path
                parse_result = entry_parser.parse_file(source_str, server_type)
            else:
                # Content string or non-existent path
                parse_result = entry_parser.parse_content(source_str, server_type)

            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | Callable[[], list[FlextLdifModels.Entry] | None]]",
                parse_result,
            )

        except (ValueError, TypeError, AttributeError, OSError) as e:
            return FlextResult[
                list[FlextLdifModels.Entry]
                | Callable[[], list[FlextLdifModels.Entry] | None]
            ].fail(f"Parsing failed: {e}")

    def parse_schema_ldif(
        self,
        file_path: Path,
        server_type: str | None = None,
    ) -> FlextResult[dict[str, list[tuple[str, list[str]]]]]:
        """Parse schema LDIF using nested SchemaParser with quirks support.

        Uses nested SchemaParser class for RFC 4512 schema parsing with
        optional server-specific quirks enhancements.

        Args:
            file_path: Path to schema LDIF file
            server_type: Optional server type for quirks handling

        Returns:
            FlextResult containing dict with schema modifications

        Example:
            result = parser.parse_schema_ldif(Path("schema.ldif"), "oud")

        """
        try:
            if not file_path.exists():
                return FlextResult[dict[str, list[tuple[str, list[str]]]]].fail(
                    f"Schema file not found: {file_path}",
                )

            # Initialize nested SchemaParser
            schema_parser = self.SchemaParser(
                self._quirk_registry,
                logger=self._logger,
            )

            # Parse schema file with quirks support
            effective_server_type = server_type or FlextLdifConstants.ServerTypes.RFC
            parse_result = schema_parser.parse_file(
                file_path,
                server_type=effective_server_type,
                parse_attributes=True,
                parse_objectclasses=True,
            )

            if parse_result.is_failure:
                return FlextResult[dict[str, list[tuple[str, list[str]]]]].fail(
                    f"Failed to parse schema: {parse_result.error}",
                )

            schema_data = parse_result.unwrap()

            # Extract schema data and convert to modifications format
            attributes_dict = schema_data.get(
                FlextLdifConstants.DictKeys.ATTRIBUTES,
                {},
            )
            objectclasses_dict = schema_data.get(
                FlextLdifConstants.DictKeys.OBJECTCLASSES,
                {},
            )

            modifications: dict[str, list[tuple[str, list[str]]]] = {"add": []}

            # Add attributeTypes
            if isinstance(attributes_dict, dict):
                for attr_data in attributes_dict.values():
                    modifications["add"].append((
                        "attributeTypes",
                        [str(attr_data)] if attr_data else [],
                    ))

            # Add objectClasses
            if isinstance(objectclasses_dict, dict):
                for oc_data in objectclasses_dict.values():
                    modifications["add"].append((
                        "objectClasses",
                        [str(oc_data)] if oc_data else [],
                    ))

            return FlextResult[dict[str, list[tuple[str, list[str]]]]].ok(modifications)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, list[tuple[str, list[str]]]]].fail(
                f"Failed to parse schema LDIF: {e}",
            )

    def parse_with_auto_detection(
        self,
        source: Path | str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF with auto-detection using nested EntryParser.

        Uses nested EntryParser to parse with automatic server type detection
        and appropriate quirks selection.

        Args:
            source: Path to LDIF file or LDIF content as string

        Returns:
            FlextResult with list of parsed LDIF entries

        Example:
            result = parser.parse_with_auto_detection(Path("data.ldif"))

        """
        try:
            # Detect server type from content
            detection_result = self.detect_server_type(
                ldif_path=Path(source)
                if isinstance(source, str) and Path(source).exists()
                else None,
                ldif_content=source
                if isinstance(source, str) and not Path(source).exists()
                else None,
            )

            if detection_result.is_failure:
                self._logger.warning(
                    f"Server detection failed: {detection_result.error}, using RFC",
                )
                server_type = FlextLdifConstants.ServerTypes.RFC
            else:
                detected = detection_result.unwrap()
                server_type = detected.detected_server_type

            # Initialize nested EntryParser
            entry_parser = self.EntryParser(
                self._quirk_registry,
                self._entry_quirks,
                self._acl_service,
                logger=self._logger,
            )

            # Parse with detected server type
            if isinstance(source, str) and Path(source).exists():
                return entry_parser.parse_file(source, server_type)
            return entry_parser.parse_content(str(source), server_type)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Auto-detection parsing failed: {e}",
            )

    def parse_relaxed(
        self,
        source: Path | str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF with relaxed mode using nested EntryParser.

        Uses nested EntryParser with server_type="relaxed" for lenient parsing
        of broken or non-compliant LDIF files.

        Args:
            source: Path to LDIF file or LDIF content as string

        Returns:
            FlextResult with list of parsed LDIF entries

        Example:
            result = parser.parse_relaxed(Path("broken.ldif"))

        """
        try:
            # Initialize nested EntryParser
            entry_parser = self.EntryParser(
                self._quirk_registry,
                self._entry_quirks,
                self._acl_service,
                logger=self._logger,
            )

            # Parse with relaxed mode quirks
            if isinstance(source, str) and Path(source).exists():
                return entry_parser.parse_file(
                    source,
                    server_type=FlextLdifConstants.ServerTypes.RELAXED,
                )
            return entry_parser.parse_content(
                str(source),
                server_type=FlextLdifConstants.ServerTypes.RELAXED,
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Relaxed parsing failed: {e}",
            )

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[FlextLdifModels.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Analyzes LDIF content to identify the source LDAP server type
        using pattern matching and heuristics.

        Args:
            ldif_path: Path to LDIF file
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with detection results containing:
            - detected_server_type: "oid" | "oud" | "openldap" | ...
            - confidence: 0.0-1.0
            - scores: {server_type: score, ...}
            - patterns_found: [pattern1, pattern2, ...]
            - is_confident: bool

        Example:
            result = parser.detect_server_type(ldif_path=Path("data.ldif"))
            if result.is_success:
                detected = result.unwrap()
                print(f"Server type: {detected.detected_server_type}")
                print(f"Confidence: {detected.confidence:.2%}")

        """
        result = self._lazy_client.detect_server_type(
            ldif_path=ldif_path,
            ldif_content=ldif_content,
        )
        if result.is_success:
            return FlextResult[FlextLdifModels.ServerDetectionResult].ok(result.value)
        return FlextResult[FlextLdifModels.ServerDetectionResult].fail(result.error)

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[str]:
        """Get the effective LDAP server type that will be used for parsing.

        Resolves the effective server type based on configuration priority:
        1. Relaxed mode (if enabled)
        2. Manual override (if detection_mode is "manual")
        3. Auto-detection (if detection_mode is "auto")
        4. RFC-only (if detection_mode is "disabled")

        Args:
            ldif_path: Optional path to LDIF file for auto-detection

        Returns:
            FlextResult with the server type string that will be used

        Example:
            # Get effective server type before parsing
            result = parser.get_effective_server_type(Path("directory.ldif"))
            if result.is_success:
                server_type = result.unwrap()
                print(f"Will use {server_type} quirks")

        """
        return self._lazy_client.get_effective_server_type(ldif_path)

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[str]:
        """Write LDIF entries to string or file.

        Delegates to FlextLdifClient for RFC 2849 compliant LDIF writing.

        Args:
            entries: List of LDIF entries to write
            output_path: Optional path to write LDIF file. If None, returns LDIF string.

        Returns:
            FlextResult containing LDIF content as string (if output_path is None)
            or success message (if output_path provided)

        Example:
            # Write to string
            result = parser.write(entries)
            if result.is_success:
                ldif_content = result.unwrap()

            # Write to file
            result = parser.write(entries, Path("output.ldif"))

        """
        return self._lazy_client.write_ldif(entries, output_path)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifModels.MigrationPipelineResult]:
        """Migrate LDIF data between different LDAP server types.

        Delegates to FlextLdifClient for server-agnostic LDIF migration.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        Example:
            result = parser.migrate(
                input_dir=Path("data/oid"),
                output_dir=Path("data/oud"),
                from_server="oid",
                to_server="oud",
                process_schema=True,
                process_entries=True
            )
            if result.is_success:
                stats = result.unwrap()
                print(f"Migrated {stats.total_entries} entries")

        """
        return self._lazy_client.migrate_files(
            input_dir,
            output_dir,
            from_server,
            to_server,
            process_schema=process_schema,
            process_entries=process_entries,
        )


__all__ = ["FlextLdifParserService"]
