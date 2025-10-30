"""LDIF client implementation.

This module implements the core business logic for LDIF operations including
parsing, writing, validation, and migration. The FlextLdifClient class is
used by the FlextLdif facade to perform actual operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

from flext_core import FlextContainer, FlextContext, FlextResult, FlextService
from pydantic import PrivateAttr

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers import (
    FlextLdifServersAd,
    FlextLdifServersApache,
    FlextLdifServersDs389,
    FlextLdifServersNovell,
    FlextLdifServersOid,
    FlextLdifServersOpenldap,
    FlextLdifServersOpenldap1,
    FlextLdifServersOud,
    FlextLdifServersRelaxed,
    FlextLdifServersTivoli,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.schema import FlextLdifSchemaValidator
from flext_ldif.services.server_detector import FlextLdifServerDetector
from flext_ldif.services.statistics import FlextLdifStatisticsService
from flext_ldif.services.writer import FlextLdifWriterService  # unified writer
from flext_ldif.typings import ServiceT

if TYPE_CHECKING:
    from flext_ldif.services.migration_pipeline import FlextLdifMigrationPipeline


class FlextLdifClient(FlextService[FlextLdifModels.ClientStatus]):
    """Main client implementation for LDIF processing operations.

    This class contains all the actual business logic for LDIF operations,
    providing a clean separation between the thin API facade and the
    implementation details.

    The client manages:
    - Service initialization and dependency injection via FlextContainer
    - CQRS handler setup and orchestration via FlextDispatcher
    - Event publishing via FlextBus for domain events
    - Default quirk registration for all supported LDAP servers
    - Business logic delegation to appropriate services
    - Context management with correlation tracking
    - Processor orchestration for batch and parallel operations

    """

    # Pydantic v2 private attributes (CRITICAL for Pydantic model initialization)
    # These MUST be declared at class level for Pydantic to handle them correctly
    # Note: _bus is inherited from FlextService, no need to redeclare
    _container: FlextContainer | None = PrivateAttr(
        default_factory=FlextContainer.get_global,
    )
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)
    _config: FlextLdifConfig | None = PrivateAttr(default=None)

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF client with optional configuration.

        Args:
        config: Optional LDIF configuration. If not provided,
        uses global singleton instance.

        """
        # Store config for lazy initialization in properties
        object.__setattr__(self, "_init_config_value", config)

        # Call Pydantic/FlextService initialization
        super().__init__()

    def model_post_init(self, _context: dict[str, object] | None, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes.

        Args:
        _context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize private attributes that parent's __init__ may access
        self._config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
        # Initialize context as empty dict (not bound to global)
        self._context = {}
        self._handlers = {}

        # Ensure components are initialized

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        # Log config ONCE without binding to global context
        if self.logger and self._config:
            config_info: dict[str, object] = {
                "ldif_encoding": self._config.ldif_encoding,
                "strict_rfc_compliance": self._config.strict_rfc_compliance,
                "ldif_chunk_size": self._config.ldif_chunk_size,
                "max_workers": self._config.max_workers,
            }
            self._log_config_once(config_info, message="FlextLdif client initialized")
            self.logger.debug("CQRS handlers and default quirks registered")

    def execute(self) -> FlextResult[FlextLdifModels.ClientStatus]:
        """Execute client self-check and return status.

        Returns:
        FlextResult containing client status and configuration

        """
        try:
            config = self.config
            client_status = FlextLdifModels.ClientStatus(
                status=FlextLdifConstants.DictKeys.INITIALIZED,
                services=FlextLdifConstants.DictKeys.SERVICE_NAMES,
                config={"default_encoding": config.ldif_encoding},
            )
            return FlextResult[FlextLdifModels.ClientStatus].ok(client_status)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ClientStatus].fail(
                f"Client status check failed: {e}",
            )

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container."""
        container = self.container

        # Register quirk registry FIRST (required by writer/parsers)
        quirk_registry = FlextLdifRegistry()
        container.register("quirk_registry", quirk_registry)

        # Register unified writer service (primary)
        # Uses config from self._config or creates default FlextLdifConfig
        config = self._config or FlextLdifConfig()
        unified_writer = FlextLdifWriterService(
            config=config,
            quirk_registry=quirk_registry,
        )
        container.register("writer", unified_writer)

        # DEPRECATED: Register as "rfc_writer" for backward compatibility
        # Maps to unified writer for consistent behavior
        container.register("rfc_writer", unified_writer)

        # Register schema validator
        container.register("schema_validator", FlextLdifSchemaValidator())

        # Register migration pipeline (params provided at call time by handlers)
        def migration_pipeline_factory(
            params: dict[str, object] | None,
        ) -> FlextLdifMigrationPipeline:
            from flext_ldif.services.migration_pipeline import (
                FlextLdifMigrationPipeline,
            )

            if params is None:
                params = {}
            return FlextLdifMigrationPipeline(
                params=params,
                source_server_type=str(
                    params.get(
                        "source_server_type", FlextLdifConstants.ServerTypes.OID
                    ),
                ),
                target_server_type=str(
                    params.get(
                        "target_server_type", FlextLdifConstants.ServerTypes.OUD
                    ),
                ),
            )

        container.register("migration_pipeline", migration_pipeline_factory)

    def _register_default_quirks(self) -> None:
        """Auto-register all default server quirks."""
        container = self.container
        logger = self.logger

        # Get quirk registry from container using helper
        registry = self._get_service_typed(
            container,
            "quirk_registry",
            FlextLdifRegistry,
        )
        if registry is None:
            logger.warning(
                "Quirk registry not available, skipping default quirk registration",
            )
            return

        # Register complete implementations using nested Schema classes
        complete_quirks: list[FlextLdifServersBase.Schema] = [
            FlextLdifServersOid.Schema(
                server_type=FlextLdifConstants.ServerTypes.OID,
                priority=10,
            ),
            FlextLdifServersOud.Schema(
                server_type=FlextLdifConstants.ServerTypes.OUD,
                priority=10,
            ),
            FlextLdifServersOpenldap.Schema(
                server_type=FlextLdifConstants.ServerTypes.OPENLDAP2,
                priority=10,
            ),
            FlextLdifServersOpenldap1.Schema(
                server_type=FlextLdifConstants.ServerTypes.OPENLDAP1,
                priority=20,
            ),
            FlextLdifServersAd.Schema(
                server_type=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
                priority=15,
            ),
            FlextLdifServersApache.Schema(
                server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                priority=15,
            ),
            FlextLdifServersDs389.Schema(
                server_type=FlextLdifConstants.LdapServers.DS_389,
                priority=15,
            ),
            FlextLdifServersNovell.Schema(
                server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
                priority=15,
            ),
            FlextLdifServersTivoli.Schema(
                server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
                priority=15,
            ),
        ]

        # Register relaxed mode quirks using nested Schema class
        relaxed = [
            FlextLdifServersRelaxed.Schema(
                server_type=FlextLdifConstants.ServerTypes.RELAXED,
                priority=200,
            ),
        ]
        complete_quirks.extend(relaxed)

        # Register stub implementations (for future completion)
        stub_quirks: list[FlextLdifServersBase.Schema] = []

        all_quirks = complete_quirks + stub_quirks

        # Register schema quirks and their nested ACL/Entry quirks
        for schema_quirk in all_quirks:
            # Register schema quirk
            schema_result = registry.register_schema_quirk(schema_quirk)
            if schema_result.is_failure:
                logger.error(f"Failed to register schema quirk: {schema_result.error}")
                continue

            # Note: Schema quirks don't have nested ACL/Entry quirks

            # Note: Schema quirks don't have nested ACL/Entry quirks

            # Note: Schema quirks don't have nested ACL/Entry quirks

            # Note: Schema quirks don't have nested ACL/Entry quirks

    def _get_service_typed(
        self,
        container: FlextContainer,
        service_name: str,
        expected_type: type[ServiceT],
    ) -> ServiceT | None:
        """Helper to retrieve and type-narrow services from container.

        Consolidates service retrieval pattern: get → unwrap → type check.

        Args:
        container: The dependency injection container
        service_name: Name of the service to retrieve
        expected_type: Expected type for type narrowing

        Returns:
        Service instance if found and correct type, None otherwise

        """
        service_result = container.get(service_name)
        if service_result.is_failure:
            return None

        service_obj = service_result.unwrap()
        # Type narrowing via isinstance - MyPy recognizes this pattern
        if isinstance(service_obj, expected_type):
            return service_obj

        return None

    # Handler initialization removed - using direct service calls

    # =========================================================================
    # BUSINESS LOGIC METHODS
    # =========================================================================

    def write_ldif(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
        entries: List of LDIF entries to write
        output_path: Optional path to write LDIF file. If None, returns LDIF string.

        Returns:
        FlextResult containing LDIF content as string (if output_path is None)
        or success message (if output_path provided)

        """
        container = self.container

        # Get the unified writer from container using helper
        writer = self._get_service_typed(container, "writer", FlextLdifWriterService)
        if not isinstance(writer, FlextLdifWriterService):
            return FlextResult[str].fail("Failed to retrieve unified writer service")

        # Write to string or file based on output_path parameter
        if output_path:
            # Write directly to file using unified writer
            write_result = writer.write(entries=entries, output_path=output_path)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write entries to file: {write_result.error}",
                )

            return FlextResult[str].ok(
                f"Successfully wrote {len(entries)} entries to {output_path}",
            )
        # Write to string using unified writer
        content_result = writer.write_to_string(entries=entries)
        if content_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to write entries to string: {content_result.error}",
            )

        return FlextResult[str].ok(content_result.unwrap())

    def migrate_files(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifModels.MigrationPipelineResult]:
        """Migrate LDIF data between different LDAP server types from files.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        """
        try:
            from flext_ldif.services.migration_pipeline import (
                FlextLdifMigrationPipeline,
            )

            params: dict[str, object] = {
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": process_schema,
                "process_entries": process_entries,
            }

            pipeline = FlextLdifMigrationPipeline(
                params=params,
                source_server_type=from_server,
                target_server_type=to_server,
            )

            migration_result = pipeline.execute()

            if migration_result.is_failure:
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    migration_result.error or "Migration failed",
                )

            return FlextResult[FlextLdifModels.MigrationPipelineResult].ok(
                migration_result.unwrap(),
            )

        except (ValueError, TypeError, AttributeError) as e:
            logger = self.logger
            logger.exception("Migration failed")
            return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                f"Migration failed: {e}",
            )

    def detect_encoding(self, content: bytes) -> FlextResult[str]:
        """Detect encoding of LDIF content bytes per RFC 2849.

        RFC 2849 mandates UTF-8 encoding for LDIF files.
        Returns error if UTF-8 decode fails (file is not RFC-compliant).

        Args:
            content: Raw bytes to detect encoding from

        Returns:
            FlextResult containing "utf-8" on success
            Failure if content is not valid UTF-8 (non-RFC compliant)

        Example:
            >>> with open("data.ldif", "rb") as f:
            ...     raw_bytes = f.read()
            >>> result = client.detect_encoding(raw_bytes)
            >>> if result.is_success:
            ...     encoding = result.unwrap()  # "utf-8"
            ... else:
            ...     print(f"Not RFC 2849 compliant: {result.error}")

        """
        try:
            # RFC 2849 requires UTF-8 encoding
            content.decode("utf-8")
            return FlextResult[str].ok("utf-8")
        except UnicodeDecodeError as e:
            # File is not RFC 2849 compliant - report error don't hide it
            return FlextResult[str].fail(
                f"LDIF content is not valid UTF-8 (RFC 2849 violation): "
                f"Invalid byte at position {e.start}: {e.reason}",
            )
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to detect encoding: {e}")

    def normalize_encoding(
        self,
        content: str,
        target_encoding: str = "utf-8",
    ) -> FlextResult[str]:
        """Normalize text content to target encoding.

        Encodes content to target encoding and decodes back to ensure
        all characters are representable in target encoding.

        Args:
            content: Text content to normalize
            target_encoding: Target encoding (default: "utf-8")

        Returns:
            FlextResult containing normalized content string

        Example:
            >>> result = client.normalize_encoding(content, "utf-8")
            >>> normalized = result.unwrap()

        """
        try:
            # Encode to target encoding and decode back (ensures valid representation)
            normalized = content.encode(target_encoding).decode(target_encoding)
            return FlextResult[str].ok(normalized)
        except UnicodeEncodeError as e:
            msg = f"Content has characters not representable in {target_encoding}: {e}"
            return FlextResult[str].fail(msg)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(
                f"Failed to normalize encoding to {target_encoding}: {e}",
            )

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        r"""Validate basic LDIF syntax structure.

        Performs basic validation checking for:
        - Presence of at least one "dn:" line (RFC 2849 requirement)
        - Non-empty content

        Note: This is a basic syntax check. For full RFC 2849 validation,
        use parse_ldif() which performs complete parsing.

        Args:
            content: LDIF content string to validate

        Returns:
            FlextResult containing True if valid basic syntax, False otherwise

        Example:
            >>> ldif_content = "dn: cn=test,dc=example,dc=com\\ncn: test\\n"
            >>> result = client.validate_ldif_syntax(ldif_content)
            >>> is_valid = result.unwrap()  # True

        """
        try:
            # Check non-empty
            if not content or not content.strip():
                return FlextResult[bool].ok(False)

            # Check for at least one "dn:" line (RFC 2849 requirement)
            # LDIF entries MUST start with "dn:"
            if FlextLdifConstants.Format.DN_PREFIX.lower() not in content.lower():
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to validate LDIF syntax: {e}")

    def count_ldif_entries(self, content: str) -> FlextResult[int]:
        r"""Count number of LDIF entries in content.

        Counts entries by counting empty lines between entries.
        RFC 2849 specifies that entries are separated by blank lines.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing entry count

        Example:
            >>> ldif_content = (
            ...     "dn: cn=test1,dc=example,dc=com\\n"
            ...     "cn: test1\\n\\n"
            ...     "dn: cn=test2,dc=example,dc=com\\n"
            ...     "cn: test2\\n"
            ... )
            >>> result = client.count_ldif_entries(ldif_content)
            >>> count = result.unwrap()  # 2

        """
        try:
            if not content or not content.strip():
                return FlextResult[int].ok(0)

            # Count entries by counting "dn:" lines (RFC 2849: each starts with dn:)
            dn_count = content.lower().count(
                FlextLdifConstants.Format.DN_PREFIX.lower(),
            )

            # Ensure at least 1 entry if content exists
            count = max(1, dn_count) if content.strip() else 0

            return FlextResult[int].ok(count)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[int].fail(f"Failed to count LDIF entries: {e}")

    # =========================================================================
    # QUIRKS MANAGEMENT
    # =========================================================================

    def register_quirk(
        self,
        quirk: FlextLdifServersBase.Schema
        | FlextLdifServersBase.Acl
        | FlextLdifServersBase.Entry,
        quirk_type: str = "schema",
    ) -> FlextResult[None]:
        """Register a custom quirk for server-specific processing.

        Args:
            quirk: Quirk instance to register
            quirk_type: Type of quirk ("schema", "acl", "entry")

        Returns:
            FlextResult indicating success or failure

        """
        # Validate quirk_type
        if quirk_type not in FlextLdifConstants.DictKeys.QUIRK_TYPES:
            return FlextResult[None].fail(f"Invalid quirk type: {quirk_type}")

        container = self.container

        # Get quirk registry from container using helper
        registry = self._get_service_typed(
            container,
            "quirk_registry",
            FlextLdifRegistry,
        )
        if not isinstance(registry, FlextLdifRegistry):
            return FlextResult[None].fail("Failed to retrieve quirk registry")

        # Use dispatch dict pattern instead of if/elif chain
        dispatch: dict[
            str,
            tuple[type, Callable[[FlextLdifRegistry, object], FlextResult[None]]],
        ] = {
            FlextLdifConstants.DictKeys.SCHEMA_QUIRK: (
                FlextLdifServersBase.Schema,
                lambda reg, q: reg.register_schema_quirk(
                    cast("FlextLdifServersBase.Schema", q),
                ),
            ),
            FlextLdifConstants.DictKeys.ACL_QUIRK: (
                FlextLdifServersBase.Acl,
                lambda reg, q: reg.register_acl_quirk(
                    cast("FlextLdifServersBase.Acl", q),
                ),
            ),
            FlextLdifConstants.DictKeys.ENTRY_QUIRK: (
                FlextLdifServersBase.Entry,
                lambda reg, q: reg.register_entry_quirk(
                    cast("FlextLdifServersBase.Entry", q),
                ),
            ),
        }

        expected_type, register_fn = dispatch[quirk_type]
        if not isinstance(quirk, expected_type):
            qname = type(quirk).__name__
            expected_name = expected_type.__name__
            return FlextResult[None].fail(f"Quirk must be {expected_name}, got {qname}")

        return register_fn(registry, quirk)

    # =========================================================================
    # INFRASTRUCTURE ACCESS
    # =========================================================================

    @property
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance with lazy initialization."""
        if self._config is None:
            self._config = (
                getattr(self, "_init_config_value", None) or FlextLdifConfig()
            )
        # Type narrowing: _config cannot be None after initialization above
        if self._config is None:
            msg = "Configuration initialization failed"
            raise RuntimeError(msg)
        return self._config

    @property
    def handlers(self) -> dict[str, object]:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container."""
        if self._container is None:
            msg = "FlextContainer must be initialized"
            raise RuntimeError(msg)
        # Type narrowed by None check above
        return self._container

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if not self._context:
            # Initialize with empty dict
            self._context = {}
        # Return as FlextContext type (which is a dict-like context object)
        return cast("FlextContext", self._context)

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[str]:
        """Get the effective server type based on configuration.

        Applies the following logic:
        1. If enable_relaxed_parsing: return "relaxed"
        2. If quirks_detection_mode == "manual": return quirks_server_type
        3. If quirks_detection_mode == "auto": detect from LDIF content
        4. Default: return server_type from config

        Args:
            ldif_path: Optional path for auto-detection

        Returns:
            FlextResult with effective server type

        """
        try:
            config = self.config

            # Relaxed mode takes precedence
            if config.enable_relaxed_parsing:
                return FlextResult[str].ok(FlextLdifConstants.ServerTypes.RELAXED)

            # Manual mode uses specified server type
            if config.quirks_detection_mode == "manual":
                if config.quirks_server_type:
                    return FlextResult[str].ok(config.quirks_server_type)
                return FlextResult[str].fail(
                    "Manual mode requires quirks_server_type to be set",
                )

            # Auto-detection mode
            if config.quirks_detection_mode == "auto" and ldif_path:
                detector = FlextLdifServerDetector()
                detection_result = detector.detect_server_type(ldif_path=ldif_path)
                if detection_result.is_success:
                    detected_data = detection_result.unwrap()
                    # ServerDetectionResult is now a Pydantic model
                    server_type = (
                        detected_data.detected_server_type or config.server_type
                    )
                    return FlextResult[str].ok(server_type)

            # Default to configured server type
            return FlextResult[str].ok(config.server_type)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Error determining server type: {e}")

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[FlextLdifModels.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Args:
            ldif_path: Path to LDIF file
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with detection results including:
            - detected_server_type: The detected server type
            - confidence: Confidence score (0.0-1.0)
            - is_confident: Whether detection confidence is high

        """
        try:
            detector = FlextLdifServerDetector()
            return detector.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                f"Server detection failed: {e}",
            )

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        strict: bool = False,
    ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate
            strict: If True, apply strict validation rules (check required attrs)

        Returns:
            FlextResult containing validation result with errors/warnings

        Example:
            >>> ldif = FlextLdif()
            >>> result = ldif.parse(Path("data.ldif"))
            >>> if result.is_success:
            ...     entries = result.unwrap()
            ...     validation = ldif.validate_entries(entries)

        """
        try:
            # Get schema validator from container
            container = self.container
            validator = self._get_service_typed(
                container,
                "schema_validator",
                FlextLdifSchemaValidator,
            )
            if validator is None:
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    "Schema validator not available in container",
                )

            # Delegate to schema validator
            return validator.validate_entries(entries, strict=strict)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                f"Entry validation failed: {e}",
            )

    def analyze_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing analysis result with statistics

        """
        try:
            # Get statistics service from container
            container = self.container
            stats_service = self._get_service_typed(
                container,
                "statistics",
                FlextLdifStatisticsService,
            )
            if stats_service is None:
                return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                    "Statistics service not available in container",
                )

            # Generate statistics
            stats_result = stats_service.generate_statistics(entries)
            if stats_result.is_success:
                # Convert to EntryAnalysisResult
                analysis_result = FlextLdifModels.EntryAnalysisResult(
                    total_entries=len(entries),
                    objectclass_distribution=stats_result.value.get(
                        "objectclass_distribution", {}
                    ),
                    attribute_distribution=stats_result.value.get(
                        "attribute_distribution", {}
                    ),
                    dn_patterns=stats_result.value.get("dn_patterns", []),
                    schema_compliance=stats_result.value.get("schema_compliance", {}),
                )
                return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(
                    analysis_result
                )

            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                stats_result.error
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                f"Entry analysis failed: {e}",
            )

    def filter(
        self,
        entries: list[FlextLdifModels.Entry],
        filter_type: str | None = None,
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: list[str] | dict[str, str | None] | None = None,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter LDIF entries using specified criteria.

        Args:
            entries: List of entries to filter
            filter_type: Type of filter to apply
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attribute filters
            mark_excluded: Whether to mark excluded entries

        Returns:
            FlextResult containing filtered entries

        """
        try:
            # Get filters service from container
            container = self.container
            filters_service = self._get_service_typed(
                container,
                "filters",
                FlextLdifFilters,
            )
            if filters_service is None:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Filters service not available in container",
                )

            # Apply filter based on type
            if (
                filter_type == FlextLdifConstants.FilterTypes.OBJECTCLASS
                and objectclass
            ):
                filtered_entries = filters_service.filter_entries_by_objectclass(
                    entries, objectclass
                )
            elif (
                filter_type == FlextLdifConstants.FilterTypes.DN_PATTERN and dn_pattern
            ):
                filtered_entries = filters_service.filter_entries_by_dn(
                    entries, dn_pattern
                )
            elif (
                filter_type == FlextLdifConstants.FilterTypes.ATTRIBUTES and attributes
            ):
                filtered_entries = filters_service.filter_entries_by_attributes(
                    entries, attributes
                )
            else:
                # No valid filter criteria provided
                filtered_entries = entries

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry filtering failed: {e}",
            )


__all__ = ["FlextLdifClient"]
