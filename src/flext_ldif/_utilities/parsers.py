"""Master class for all LDIF parsing utilities.

Python 3.13+ optimized implementation using:
- Nested classes for organized structure
- Pattern matching for cleaner control flow
- Protocol-based hooks for server customization
- Generator expressions for lazy evaluation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from typing import Protocol, TypeVar

import structlog
from flext_core import FlextResult, FlextRuntime

from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif.models import FlextLdifModels

logger = structlog.get_logger(__name__)

# Type aliases
T = TypeVar("T")
EntryAttrs = Mapping[str, list[str]]


class FlextLdifUtilitiesParsers:
    """Master class for all LDIF parsing utilities.

    Contains nested classes for each parsing operation:
    - Content: Parse LDIF content into entries
    - Attribute: Parse attribute definitions
    - ObjectClass: Parse objectClass definitions
    - Entry: Parse individual entries

    Example:
        >>> result = FlextLdifUtilitiesParsers.Content.parse(
        ...     ldif_content, "oid", oid_quirk._parse_entry
        ... )

    """

    # =========================================================================
    # CONTENT PARSER - Parse LDIF content into Entry models
    # =========================================================================

    class Content:
        """Generalized content parser with hook-based customization."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParseEntryHook(Protocol):
            """Protocol for entry parsing hooks."""

            def __call__(
                self,
                dn: str,
                attrs: EntryAttrs,
            ) -> FlextResult[FlextLdifModels.Entry]: ...

        class PreserveMetadataHook(Protocol):
            """Protocol for metadata preservation hooks."""

            def __call__(
                self,
                entry: FlextLdifModels.Entry,
                original_ldif: str,
                context: str,
            ) -> None: ...

        class TransformAttrsHook(Protocol):
            """Protocol for attribute transformation hooks."""

            def __call__(
                self,
                dn: str,
                attrs: EntryAttrs,
            ) -> tuple[str, EntryAttrs]: ...

        class PostParseHook(Protocol):
            """Protocol for post-parse entry hooks."""

            def __call__(
                self,
                entry: FlextLdifModels.Entry,
            ) -> FlextLdifModels.Entry: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass(slots=True)
        class Stats:
            """Statistics for content parsing operations."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0
            skipped: int = 0
            with_metadata: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            ldif_content: str,
            server_type: str,
            parse_entry_hook: ParseEntryHook,
            *,
            transform_attrs_hook: TransformAttrsHook | None = None,
            post_parse_hook: PostParseHook | None = None,
            preserve_metadata_hook: PreserveMetadataHook | None = None,
            skip_empty_entries: bool = True,
            log_level: str = "debug",
            ldif_parser: Callable[[str], list[tuple[str, EntryAttrs]]] | None = None,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content using hook-based configuration.

            Args:
                ldif_content: Raw LDIF content string
                server_type: Server type identifier (e.g., "rfc", "oid")
                parse_entry_hook: Hook to parse (dn, attrs) into Entry
                transform_attrs_hook: Optional hook to transform attrs before parsing
                post_parse_hook: Optional hook to transform entry after parsing
                preserve_metadata_hook: Optional hook to preserve original LDIF
                skip_empty_entries: Skip entries with no attributes
                log_level: Logging verbosity ("debug", "info", "warning")
                ldif_parser: Optional custom LDIF parser

            Returns:
                FlextResult with list of parsed Entry objects

            Example:
                >>> result = FlextLdifUtilitiesParsers.Content.parse(
                ...     ldif_content, "oid", oid_quirk._parse_entry
                ... )

            """
            # Early return for empty content
            if not ldif_content.strip():
                logger.debug("Empty LDIF content", server_type=server_type)
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            try:
                # Parse LDIF using provided parser or default
                parser = ldif_parser or FlextLdifUtilitiesParser.parse_ldif_lines
                parsed_entries_raw = parser(ldif_content)

                # Convert to proper type (dict -> Mapping for type compatibility)
                parsed_entries: list[tuple[str, EntryAttrs]] = [
                    (dn, attrs) for dn, attrs in parsed_entries_raw
                ]

                # Initialize stats tracker
                stats = FlextLdifUtilitiesParsers.Content.Stats(
                    total_entries=len(parsed_entries),
                )

                # Process entries using generator
                entries = list(
                    FlextLdifUtilitiesParsers.Content.process_entries(
                        parsed_entries,
                        parse_entry_hook,
                        transform_attrs_hook,
                        post_parse_hook,
                        preserve_metadata_hook,
                        skip_empty_entries=skip_empty_entries,
                        stats=stats,
                    ),
                )

                # Log final stats
                if log_level == "debug":
                    logger.debug(
                        "Parsed %s LDIF content",
                        server_type.upper(),
                        total=stats.total_entries,
                        successful=stats.successful,
                        failed=stats.failed,
                        with_metadata=stats.with_metadata,
                    )

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except Exception as e:
                logger.exception(
                    "Failed to parse LDIF content",
                    server_type=server_type,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse {server_type} LDIF: {e}",
                )

        @staticmethod
        def process_entries(
            parsed_entries: list[tuple[str, EntryAttrs]],
            parse_entry_hook: ParseEntryHook,
            transform_attrs_hook: TransformAttrsHook | None,
            post_parse_hook: PostParseHook | None,
            preserve_metadata_hook: PreserveMetadataHook | None,
            *,
            skip_empty_entries: bool = True,
            stats: Stats,
        ) -> Generator[FlextLdifModels.Entry]:
            """Process parsed entries using hooks.

            Args:
                parsed_entries: List of (dn, attrs) tuples from parser
                parse_entry_hook: Hook to parse (dn, attrs) into Entry
                transform_attrs_hook: Optional hook to transform attrs before parsing
                post_parse_hook: Optional hook to transform entry after parsing
                preserve_metadata_hook: Optional hook to preserve original LDIF
                skip_empty_entries: Skip entries with no attributes
                stats: Statistics tracker

            Yields:
                Entry models parsed from LDIF content

            """
            for idx, (original_dn, original_attrs) in enumerate(parsed_entries):
                # Skip empty entries if configured
                if skip_empty_entries and not original_attrs:
                    stats.skipped += 1
                    continue

                # Apply transform hook if provided
                if transform_attrs_hook:
                    transformed_dn, transformed_attrs = transform_attrs_hook(
                        original_dn,
                        original_attrs,
                    )
                    current_dn = transformed_dn
                    current_attrs = transformed_attrs
                else:
                    current_dn = original_dn
                    current_attrs = original_attrs

                # Reconstruct original LDIF
                original_ldif = (
                    "\n".join(
                        [f"dn: {current_dn}"]
                        + [
                            f"{attr}: {val}"
                            for attr, vals in current_attrs.items()
                            for val in vals
                        ],
                    )
                    + "\n"
                )

                # Parse entry using hook
                match parse_entry_hook(current_dn, current_attrs):
                    case FlextResult(is_success=True) as result:
                        entry = result.unwrap()

                        # Apply post-parse hook if provided
                        if post_parse_hook:
                            entry = post_parse_hook(entry)

                        # Preserve metadata
                        if entry.metadata and preserve_metadata_hook:
                            preserve_metadata_hook(
                                entry,
                                original_ldif,
                                "entry_original_ldif",
                            )
                            stats.with_metadata += 1
                        elif entry.metadata:
                            # Type narrowing: convert internal QuirkMetadata to public QuirkMetadata
                            if not isinstance(
                                entry.metadata,
                                FlextLdifModels.QuirkMetadata,
                            ):
                                metadata_public = (
                                    FlextLdifModels.QuirkMetadata.model_validate(
                                        entry.metadata.model_dump(),
                                    )
                                )
                            else:
                                metadata_public = entry.metadata
                            FlextLdifUtilitiesMetadata.preserve_original_ldif_content(
                                metadata=metadata_public,
                                ldif_content=original_ldif,
                                context="entry_original_ldif",
                            )
                            stats.with_metadata += 1

                        stats.successful += 1
                        yield entry

                    case FlextResult(is_failure=True) as result:
                        stats.failed += 1
                        logger.error(
                            "Failed to parse entry",
                            entry_dn=current_dn[:50] if current_dn else None,
                            entry_index=idx + 1,
                            error=str(result.error),
                        )

    # =========================================================================
    # ATTRIBUTE PARSER - Parse attribute type definitions
    # =========================================================================

    class Attribute:
        """Generalized attribute definition parser."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParseCoreHook(Protocol):
            """Protocol for core attribute parsing."""

            def __call__(
                self,
                definition: str,
            ) -> FlextResult[FlextLdifModels.SchemaAttribute]: ...

        class ValidateSyntaxHook(Protocol):
            """Protocol for syntax validation."""

            def __call__(self, syntax_oid: str | None) -> str | None: ...

        class EnrichMetadataHook(Protocol):
            """Protocol for metadata enrichment."""

            def __call__(
                self,
                attribute: FlextLdifModels.SchemaAttribute,
                definition: str,
            ) -> FlextLdifModels.SchemaAttribute: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            definition: str,
            server_type: str,
            parse_core_hook: ParseCoreHook,
            *,
            validate_syntax_hook: ValidateSyntaxHook | None = None,
            enrich_metadata_hook: EnrichMetadataHook | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition using hooks.

            Args:
                definition: Raw attribute type definition
                server_type: Server type identifier
                parse_core_hook: Core parsing logic
                validate_syntax_hook: Optional syntax validation
                enrich_metadata_hook: Optional metadata enrichment

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                # Parse using core hook
                result = parse_core_hook(definition)
                if result.is_failure:
                    return result

                attribute = result.unwrap()

                # Validate syntax if hook provided
                if validate_syntax_hook and attribute.syntax:
                    attribute.syntax = validate_syntax_hook(attribute.syntax)

                # Enrich metadata if hook provided
                if enrich_metadata_hook:
                    attribute = enrich_metadata_hook(attribute, definition)

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            except Exception as e:
                logger.exception("Failed to parse attribute", server_type=server_type)
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Failed to parse attribute: {e}",
                )

    # =========================================================================
    # OBJECTCLASS PARSER - Parse objectClass definitions
    # =========================================================================

    class ObjectClass:
        """Generalized objectClass definition parser."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParseCoreHook(Protocol):
            """Protocol for core objectClass parsing."""

            def __call__(
                self,
                definition: str,
            ) -> FlextResult[FlextLdifModels.SchemaObjectClass]: ...

        class ValidateStructuralHook(Protocol):
            """Protocol for structural validation."""

            def __call__(self, kind: str, sup: list[str]) -> bool: ...

        class TransformSupHook(Protocol):
            """Protocol for SUP clause transformation."""

            def __call__(self, sup: list[str]) -> list[str]: ...

        class EnrichMetadataHook(Protocol):
            """Protocol for metadata enrichment."""

            def __call__(
                self,
                objectclass: FlextLdifModels.SchemaObjectClass,
                definition: str,
            ) -> FlextLdifModels.SchemaObjectClass: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            definition: str,
            server_type: str,
            parse_core_hook: ParseCoreHook,
            *,
            validate_structural_hook: ValidateStructuralHook | None = None,
            transform_sup_hook: TransformSupHook | None = None,
            enrich_metadata_hook: EnrichMetadataHook | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition using hooks.

            Args:
                definition: Raw objectClass definition
                server_type: Server type identifier
                parse_core_hook: Core parsing logic
                validate_structural_hook: Optional structural validation
                transform_sup_hook: Optional SUP transformation
                enrich_metadata_hook: Optional metadata enrichment

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            try:
                # Parse using core hook
                result = parse_core_hook(definition)
                if result.is_failure:
                    return result

                objectclass = result.unwrap()

                # Validate structural if hook provided
                if validate_structural_hook:
                    # Convert sup to list[str] if it's a string
                    sup_list_raw = (
                        objectclass.sup
                        if FlextRuntime.is_list_like(objectclass.sup)
                        else [objectclass.sup]
                        if isinstance(objectclass.sup, str)
                        else []
                    )
                    # Type narrowing: list[object] | list[str] → list[str]
                    if not isinstance(sup_list_raw, list):
                        msg = f"Expected list, got {type(sup_list_raw)}"
                        raise TypeError(msg)
                    # Filter to only str items
                    sup_list_validate: list[str] = [
                        str(item) for item in sup_list_raw if isinstance(item, str)
                    ]
                    validate_structural_hook(
                        objectclass.kind or "STRUCTURAL",
                        sup_list_validate,
                    )

                # Transform SUP if hook provided
                if transform_sup_hook and objectclass.sup:
                    # Convert sup to list[str] if it's a string
                    sup_list_raw = (
                        objectclass.sup
                        if FlextRuntime.is_list_like(objectclass.sup)
                        else [objectclass.sup]
                        if isinstance(objectclass.sup, str)
                        else []
                    )
                    # Type narrowing: list[object] | list[str] → list[str]
                    if not isinstance(sup_list_raw, list):
                        msg = f"Expected list, got {type(sup_list_raw)}"
                        raise TypeError(msg)
                    # Filter to only str items
                    sup_list_transform: list[str] = [
                        str(item) for item in sup_list_raw if isinstance(item, str)
                    ]
                    objectclass.sup = transform_sup_hook(sup_list_transform)

                # Enrich metadata if hook provided
                if enrich_metadata_hook:
                    objectclass = enrich_metadata_hook(objectclass, definition)

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

            except Exception as e:
                logger.exception("Failed to parse objectClass", server_type=server_type)
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"Failed to parse objectClass: {e}",
                )

    # =========================================================================
    # ENTRY PARSER - Parse individual LDIF entries
    # =========================================================================

    class Entry:
        """Generalized entry parser."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class CreateEntryHook(Protocol):
            """Protocol for entry creation."""

            def __call__(
                self,
                dn: str,
                attrs: EntryAttrs,
            ) -> FlextResult[FlextLdifModels.Entry]: ...

        class BuildMetadataHook(Protocol):
            """Protocol for metadata building."""

            def __call__(
                self,
                dn: str,
                attrs: EntryAttrs,
            ) -> FlextLdifModels.QuirkMetadata | None: ...

        class NormalizeDnHook(Protocol):
            """Protocol for DN normalization."""

            def __call__(self, dn: str) -> str: ...

        class TransformAttrsHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(self, attrs: EntryAttrs) -> EntryAttrs: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            dn: str,
            attrs: EntryAttrs,
            server_type: str,
            create_entry_hook: CreateEntryHook,
            *,
            build_metadata_hook: BuildMetadataHook | None = None,
            normalize_dn_hook: NormalizeDnHook | None = None,
            transform_attrs_hook: TransformAttrsHook | None = None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse entry using hooks.

            Args:
                dn: Distinguished name
                attrs: Entry attributes
                server_type: Server type identifier
                create_entry_hook: Entry creation logic
                build_metadata_hook: Optional metadata building
                normalize_dn_hook: Optional DN normalization
                transform_attrs_hook: Optional attribute transformation

            Returns:
                FlextResult with parsed Entry model

            """
            try:
                # Normalize DN if hook provided
                if normalize_dn_hook:
                    dn = normalize_dn_hook(dn)

                # Transform attrs if hook provided
                if transform_attrs_hook:
                    attrs = transform_attrs_hook(attrs)

                # Create entry using hook
                result = create_entry_hook(dn, attrs)
                if result.is_failure:
                    return result

                entry = result.unwrap()

                # Build metadata if hook provided
                if build_metadata_hook:
                    metadata = build_metadata_hook(dn, attrs)
                    if metadata:
                        entry.metadata = metadata

                return FlextResult[FlextLdifModels.Entry].ok(entry)

            except Exception as e:
                logger.exception(
                    "Failed to parse entry",
                    server_type=server_type,
                    dn=dn[:50] if dn else None,
                )
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )
