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

from collections.abc import Generator, Mapping
from dataclasses import dataclass
from typing import Protocol, TypeVar

import structlog
from flext_core import FlextResult
from flext_core.utilities import FlextUtilities

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif.models import FlextLdifModels

logger = structlog.get_logger(__name__)

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities

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
            config: FlextLdifModelsConfig.LdifContentParseConfig | None = None,
            **kwargs: object,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content using hook-based configuration.

            Args:
                config: LdifContentParseConfig with all parsing parameters
                **kwargs: Optional parameters for LdifContentParseConfig (ldif_content,
                    server_type, parse_entry_hook, transform_attrs_hook, post_parse_hook,
                    preserve_metadata_hook, skip_empty_entries, log_level, ldif_parser) -
                    used only if config is None

            Returns:
                FlextResult with list of parsed Entry objects

            Example:
                >>> config = FlextLdifModelsConfig.LdifContentParseConfig(
                ...     ldif_content=content, server_type="oid",
                ...     parse_entry_hook=oid_quirk._parse_entry
                ... )
                >>> result = FlextLdifUtilitiesParsers.Content.parse(config)

            """
            # Use provided config or build from kwargs
            if config is None:
                config = FlextLdifModelsConfig.LdifContentParseConfig(**kwargs)  # type: ignore[arg-type]

            # Early return for empty content
            if not config.ldif_content.strip():
                logger.debug("Empty LDIF content", server_type=config.server_type)
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            try:
                # Parse LDIF using provided parser or default
                parser = config.ldif_parser or FlextLdifUtilitiesParser.parse_ldif_lines
                parsed_entries_raw = parser(config.ldif_content)

                # Convert to proper type (dict -> Mapping for type compatibility)
                # Direct conversion is simpler than u.process for this case
                parsed_entries: list[tuple[str, EntryAttrs]] = [
                    (dn, attrs) for dn, attrs in parsed_entries_raw
                ]

                # Initialize stats tracker
                stats = FlextLdifUtilitiesParsers.Content.Stats(
                    total_entries=len(parsed_entries),
                )

                # Process entries using generator
                process_config = FlextLdifModelsConfig.EntryProcessingConfig(
                    parsed_entries=parsed_entries,
                    parse_entry_hook=config.parse_entry_hook,
                    transform_attrs_hook=config.transform_attrs_hook,
                    post_parse_hook=config.post_parse_hook,
                    preserve_metadata_hook=config.preserve_metadata_hook,
                    skip_empty_entries=config.skip_empty_entries,
                )
                entries = list(
                    FlextLdifUtilitiesParsers.Content.process_entries(
                        process_config,
                        stats=stats,
                    ),
                )

                # Log final stats
                if config.log_level == "debug":
                    logger.debug(
                        "Parsed %s LDIF content",
                        config.server_type.upper(),
                        total=stats.total_entries,
                        successful=stats.successful,
                        failed=stats.failed,
                        with_metadata=stats.with_metadata,
                    )

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except Exception as e:
                logger.exception(
                    "Failed to parse LDIF content",
                    server_type=config.server_type,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse {config.server_type} LDIF: {e}",
                )

        @staticmethod
        def build_ldif_lines(
            current_dn: str,
            current_attrs: EntryAttrs,
        ) -> str:
            """Build LDIF lines from DN and attributes."""
            def build_attr_lines(attr_item: tuple[str, list[str]]) -> list[str]:
                """Build attribute lines for single attribute."""
                attr, vals = attr_item
                return [f"{attr}: {val}" for val in vals]
            attr_lines_result = u.process(
                list(current_attrs.items()),
                processor=build_attr_lines,
                on_error="skip",
            )
            if attr_lines_result.is_success and isinstance(attr_lines_result.value, list):
                # Flatten nested list of lines
                attr_lines = [
                    line
                    for sublist in attr_lines_result.value
                    if isinstance(sublist, list)
                    for line in sublist
                ]
            else:
                # Fallback: build lines directly from attributes
                attr_lines = [
                    f"{attr}: {val}"
                    for attr, vals in current_attrs.items()
                    for val in vals
                ]
            return "\n".join([f"dn: {current_dn}"] + attr_lines) + "\n"

        @staticmethod
        def preserve_entry_metadata(
            entry: FlextLdifModels.Entry,
            original_ldif: str,
            config: FlextLdifModelsConfig.EntryProcessingConfig,
            stats: Stats,
        ) -> None:
            """Preserve metadata for entry."""
            if entry.metadata and config.preserve_metadata_hook:
                config.preserve_metadata_hook(
                    entry,
                    original_ldif,
                    "entry_original_ldif",
                )
                stats.with_metadata += 1
            elif entry.metadata:
                # Type narrowing: convert internal QuirkMetadata to public QuirkMetadata
                if not isinstance(
                    entry.metadata,
                    FlextLdifModelsDomains.QuirkMetadata,
                ):
                    metadata_public = (
                        FlextLdifModelsDomains.QuirkMetadata.model_validate(
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

        @staticmethod
        def process_entries(
            config: FlextLdifModelsConfig.EntryProcessingConfig,
            *,
            stats: Stats,
        ) -> Generator[FlextLdifModels.Entry]:
            """Process parsed entries using hooks.

            Args:
                config: EntryProcessingConfig with all processing parameters
                stats: Statistics tracker

            Yields:
                Entry models parsed from LDIF content

            """
            for idx, (original_dn, original_attrs) in enumerate(config.parsed_entries):
                # Skip empty entries if configured
                if config.skip_empty_entries and not original_attrs:
                    stats.skipped += 1
                    continue

                # Apply transform hook if provided
                if config.transform_attrs_hook:
                    transformed_dn, transformed_attrs = config.transform_attrs_hook(
                        original_dn,
                        original_attrs,
                    )
                    current_dn = transformed_dn
                    current_attrs = transformed_attrs
                else:
                    current_dn = original_dn
                    current_attrs = original_attrs

                # Reconstruct original LDIF
                original_ldif = FlextLdifUtilitiesParsers.Content.build_ldif_lines(
                    current_dn,
                    current_attrs,
                )

                # Parse entry using hook
                match config.parse_entry_hook(current_dn, current_attrs):
                    case FlextResult(is_success=True) as result:
                        entry = result.unwrap()

                        # Apply post-parse hook if provided
                        if config.post_parse_hook:
                            entry = config.post_parse_hook(entry)

                        # Preserve metadata
                        FlextLdifUtilitiesParsers.Content.preserve_entry_metadata(
                            entry,
                            original_ldif,
                            config,
                            stats,
                        )

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
            ) -> FlextResult[FlextLdifModelsDomains.SchemaAttribute]: ...

        class ValidateSyntaxHook(Protocol):
            """Protocol for syntax validation."""

            def __call__(self, syntax_oid: str | None) -> str | None: ...

        class EnrichMetadataHook(Protocol):
            """Protocol for metadata enrichment."""

            def __call__(
                self,
                attribute: FlextLdifModelsDomains.SchemaAttribute,
                definition: str,
            ) -> FlextLdifModelsDomains.SchemaAttribute: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            definition: str,
            server_type: str,
            parse_core_hook: ParseCoreHook,
            *,
            validate_syntax_hook: ValidateSyntaxHook | None = None,
            enrich_metadata_hook: EnrichMetadataHook | None = None,
        ) -> FlextResult[FlextLdifModelsDomains.SchemaAttribute]:
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

                return FlextResult[FlextLdifModelsDomains.SchemaAttribute].ok(attribute)

            except Exception as e:
                logger.exception("Failed to parse attribute", server_type=server_type)
                return FlextResult[FlextLdifModelsDomains.SchemaAttribute].fail(
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
            ) -> FlextResult[FlextLdifModelsDomains.SchemaObjectClass]: ...

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
                objectclass: FlextLdifModelsDomains.SchemaObjectClass,
                definition: str,
            ) -> FlextLdifModelsDomains.SchemaObjectClass: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def normalize_sup_list(sup: object) -> list[str]:
            """Normalize sup to list[str]."""
            # Type narrowing for FlextRuntime.is_list_like
            if isinstance(sup, list):
                sup_list_raw = sup
            elif isinstance(sup, str):
                sup_list_raw = [sup]
            else:
                sup_list_raw = []
            if not isinstance(sup_list_raw, list):
                msg = f"Expected list, got {type(sup_list_raw)}"
                raise TypeError(msg)
            filtered_sup = u.filter(
                sup_list_raw,
                predicate=lambda item: isinstance(item, str),
            )
            if isinstance(filtered_sup, list):
                return [str(item) for item in filtered_sup]
            return []

        @staticmethod
        def parse(
            config: FlextLdifModelsConfig.ObjectClassParseConfig | None = None,
            **kwargs: object,
        ) -> FlextResult[FlextLdifModelsDomains.SchemaObjectClass]:
            """Parse objectClass definition using hooks.

            Args:
                config: ObjectClassParseConfig with all parsing parameters
                **kwargs: Optional parameters for ObjectClassParseConfig (definition,
                    server_type, parse_core_hook, validate_structural_hook,
                    transform_sup_hook, enrich_metadata_hook) - used only if config is None

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            # Use provided config or build from kwargs
            if config is None:
                config = FlextLdifModelsConfig.ObjectClassParseConfig(**kwargs)  # type: ignore[arg-type]

            try:
                # Parse using core hook
                result = config.parse_core_hook(config.definition)
                if result.is_failure:
                    return result

                objectclass = result.unwrap()

                # Validate structural if hook provided
                if config.validate_structural_hook:
                    sup_list_validate = FlextLdifUtilitiesParsers.ObjectClass.normalize_sup_list(
                        objectclass.sup,
                    )
                    config.validate_structural_hook(
                        objectclass.kind or "STRUCTURAL",
                        sup_list_validate,
                    )

                # Transform SUP if hook provided
                if config.transform_sup_hook and objectclass.sup:
                    sup_list_transform = FlextLdifUtilitiesParsers.ObjectClass.normalize_sup_list(
                        objectclass.sup,
                    )
                    objectclass.sup = config.transform_sup_hook(sup_list_transform)

                # Enrich metadata if hook provided
                if config.enrich_metadata_hook:
                    config.enrich_metadata_hook(objectclass)

                return FlextResult[FlextLdifModelsDomains.SchemaObjectClass].ok(
                    objectclass,
                )

            except Exception as e:
                logger.exception("Failed to parse objectClass", server_type=config.server_type)
                return FlextResult[FlextLdifModelsDomains.SchemaObjectClass].fail(
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
            ) -> FlextLdifModelsDomains.QuirkMetadata | None: ...

        class NormalizeDnHook(Protocol):
            """Protocol for DN normalization."""

            def __call__(self, dn: str) -> str: ...

        class TransformAttrsHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(self, attrs: EntryAttrs) -> EntryAttrs: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            config: FlextLdifModelsConfig.EntryParseConfig | None = None,
            **kwargs: object,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse entry using hooks.

            Args:
                config: EntryParseConfig with all parsing parameters (preferred)
                dn: Distinguished name (used if config is None)
                attrs: Entry attributes (used if config is None)
                server_type: Server type identifier (used if config is None)
                create_entry_hook: Entry creation logic (used if config is None)
                build_metadata_hook: Optional metadata building (used if config is None)
                normalize_dn_hook: Optional DN normalization (used if config is None)
                transform_attrs_hook: Optional attribute transformation (used if config is None)
                **kwargs: Optional parameters for EntryParseConfig (used only if config is None)

            Returns:
                FlextResult with parsed Entry model

            """
            # Use provided config or build from kwargs
            if config is None:
                config = FlextLdifModelsConfig.EntryParseConfig(**kwargs)  # type: ignore[arg-type]

            try:
                # Normalize DN if hook provided
                dn = config.dn
                if config.normalize_dn_hook:
                    dn = config.normalize_dn_hook(dn)

                # Transform attrs if hook provided
                dn_transformed = config.dn
                attrs = config.attrs
                if config.transform_attrs_hook:
                    dn_transformed, attrs = config.transform_attrs_hook(config.dn, config.attrs)
                dn = dn_transformed

                # Create entry using hook
                result = config.create_entry_hook(dn, attrs)
                if result.is_failure:
                    return result

                entry = result.unwrap()

                # Build metadata if hook provided
                if config.build_metadata_hook:
                    metadata = config.build_metadata_hook(dn, attrs)
                    if metadata:
                        entry.metadata = metadata

                return FlextResult[FlextLdifModels.Entry].ok(entry)

            except Exception as e:
                logger.exception(
                    "Failed to parse entry",
                    server_type=config.server_type,
                    dn=config.dn[:50] if config.dn else None,
                )
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )
