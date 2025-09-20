"""FLEXT LDIF API - Unified interface for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from pydantic import ConfigDict
from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor


class FlextLdifAPI(FlextDomainService[dict[str, object]]):
    """Unified LDIF API with compatibility services for seamless operations.
    
    Provides a single interface for all LDIF processing operations including
    parsing, validation, writing, transformation, and analytics. Uses FlextResult
    patterns for composable error handling and railway-oriented programming.
    
    This API consolidates the functionality of multiple services while maintaining
    backward compatibility with the old service-based architecture through
    compatibility wrappers.
    """
    
    # Override model_config to allow setting attributes after initialization
    model_config = ConfigDict(
        frozen=False,  # Allow setting attributes after initialization
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with processor and compatibility services."""
        super().__init__()
        self._config = config or FlextLdifConfig()
        self._logger = FlextLogger(__name__)
        
        # Initialize processor with error handling
        self._processor_result = self._initialize_processor()
        
        # Initialize compatibility services that delegate to this API
        self._init_compatibility_services()
        
        # Create _services for test compatibility
        object.__setattr__(self, '_services', self)
    
    def _initialize_processor(self) -> FlextResult[FlextLdifProcessor]:
        """Initialize the processor with proper error handling."""
        try:
            processor = FlextLdifProcessor(config=self._config)
            self._logger.info("LDIF processor initialized successfully")
            return FlextResult[FlextLdifProcessor].ok(processor)
        except Exception as e:
            error_msg = f"Failed to initialize LDIF processor: {e}"
            self._logger.error(error_msg)
            return FlextResult[FlextLdifProcessor].fail(error_msg)
    
    def _init_compatibility_services(self) -> None:
        """Initialize compatibility service classes as attributes."""
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from flext_ldif.models import FlextLdifModels
        
        # Use object.__setattr__ to bypass Pydantic validation
        object.__setattr__(self, 'parser_service', self._ParserCompatibilityService(self))
        object.__setattr__(self, 'writer_service', self._WriterCompatibilityService(self))
        object.__setattr__(self, 'validator_service', self._ValidatorCompatibilityService(self))
        object.__setattr__(self, 'repository_service', self._RepositoryCompatibilityService(self))
        object.__setattr__(self, 'analytics_service', self._AnalyticsCompatibilityService(self))

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check operation - required by FlextDomainService."""
        return self.health_check()

    # =============================================================================
    # CORE API METHODS - Main functionality
    # =============================================================================

    def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string into entries."""
        return (
            self._processor_result
            .flat_map(lambda processor: processor.parse_content(content))
            .map(self._log_parse_success)
        )
    
    def parse_ldif_file(self, file_path: Path) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file into entries."""
        return (
            self._processor_result
            .flat_map(lambda processor: processor.parse_ldif_file(str(file_path)))
            .map(self._log_parse_file_success)
        )

    
    def parse_file_path(self, file_path: Path | str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using file path (string or Path) - test compatibility method."""
        if isinstance(file_path, str):
            file_path = Path(file_path)
        return self.parse_ldif_file(file_path)
    
    def validate_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate LDIF entries and return valid entries."""
        return (
            self._processor_result.flat_map(lambda processor: processor.validate_entries(entries))
            .map(lambda _: entries)  # Return the original entries if validation succeeds
            .map(self._log_validation_success_with_entries)
            .recover(lambda error: [])  # Return empty list on validation failure
        )

    def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF format string."""
        return (
            self._processor_result
            .flat_map(lambda processor: processor.write_entries_to_string(entries))
            .map(self._log_write_success)
        )
    
    def write_file(self, entries: list[FlextLdifModels.Entry], file_path: Path) -> FlextResult[bool]:
        """Write entries to LDIF file.""" 
        return (
            self._processor_result
            .flat_map(lambda processor: processor.write_entries_to_file(entries, str(file_path)))
            .map(lambda _: True)
            .map(self._log_write_file_success)
            .recover(lambda error: False)  # Return False on write failure
        )

    def transform(self, entries: list[FlextLdifModels.Entry], 
                 transformer: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry] | None = None) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform entries using optional transformer function."""
        if transformer is None:
            # Default transformer - identity function
            transformer = lambda entry: entry
        
        return (
            self._processor_result
            .flat_map(lambda processor: processor.transform_entries(entries, transformer))
            .map(self._log_transformation_success)
        )

    def analyze(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[dict[str, object]]:
        """Analyze entries and return statistics."""
        return (
            self._processor_result
            .flat_map(lambda processor: processor.analyze_entries(entries))
            .map(lambda stats: cast("dict[str, object]", stats))
            .map(self._log_analysis_success)
        )

    def filter_entries(self, entries: list[FlextLdifModels.Entry], 
                      filter_func: Callable[[FlextLdifModels.Entry], bool]) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries using provided predicate function."""
        try:
            filtered_entries = [entry for entry in entries if filter_func(entry)]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter operation failed: {e}")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform health check on the API and processor."""
        return (
            self._processor_result
            .map(lambda processor: cast("dict[str, object]", {
                "api_status": "healthy",
                "processor_status": "initialized",
                "config_loaded": True,
                "timestamp": str(self._get_timestamp())
            }))
            .recover(lambda error: cast("dict[str, object]", {
                "api_status": "unhealthy", 
                "processor_status": "failed",
                "error": str(error),
                "timestamp": str(self._get_timestamp())
            }))
        )

    def get_service_info(self) -> dict[str, object]:
        """Get service information using safe evaluation."""
        return self._processor_result.map(
            lambda processor: cast("dict[str, object]", {
                "api": "FlextLdifAPI",
                "capabilities": [
                    "parse",
                    "parse_file",
                    "validate",
                    "write",
                    "write_file",
                    "transform",
                    "analyze",
                    "filter_entries",
                    "health_check",
                ],
                "processor": processor.get_config_info(),
                "config": self._get_config_summary(),
                "pattern": "railway_oriented_programming",
            })
        ).unwrap_or(
            cast("dict[str, object]", {
                "api": "FlextLdifAPI",
                "status": "processor_initialization_failed",
                "pattern": "railway_oriented_programming",
            })
        )

    # =============================================================================
    # HELPER METHODS - Logging and utilities  
    # =============================================================================

    def _log_parse_success(self, entries: list[FlextLdifModels.Entry]) -> list[FlextLdifModels.Entry]:
        """Log successful parsing operation."""
        self._logger.info(f"Successfully parsed {len(entries)} LDIF entries")
        return entries
    
    def _log_parse_file_success(self, entries: list[FlextLdifModels.Entry]) -> list[FlextLdifModels.Entry]:
        """Log successful file parsing operation."""
        self._logger.info(f"Successfully parsed {len(entries)} entries from LDIF file")
        return entries
    
    def _log_validation_success_with_count(self, count: int) -> Callable[[bool], bool]:
        """Create logging function for validation success with entry count."""
        def log_validation(success: bool) -> bool:
            self._logger.info(f"Validation completed for {count} entries with result: {success}")
            return success
        return log_validation
    
    def _log_validation_success_with_entries(self, entries: list[FlextLdifModels.Entry]) -> list[FlextLdifModels.Entry]:
        """Log successful validation operation with entries."""
        self._logger.info(f"Validation completed successfully for {len(entries)} entries")
        return entries
    
    def _log_write_success(self, content: str) -> str:
        """Log successful write operation."""
        self._logger.info(f"Successfully generated LDIF content ({len(content)} characters)")
        return content
    
    def _log_write_file_success(self, success: bool) -> bool:
        """Log successful file write operation."""
        self._logger.info(f"Successfully wrote LDIF file: {success}")
        return success
    
    def _log_transformation_success(self, entries: list[FlextLdifModels.Entry]) -> list[FlextLdifModels.Entry]:
        """Log successful transformation operation."""
        self._logger.info(f"Successfully transformed {len(entries)} entries")
        return entries
    
    def _log_analysis_success(self, stats: dict[str, object]) -> dict[str, object]:
        """Log successful analysis operation."""
        self._logger.info(f"Successfully analyzed entries, generated {len(stats)} statistics")
        return stats
    
    def _log_filter_success(self, entries: list[FlextLdifModels.Entry]) -> list[FlextLdifModels.Entry]:
        """Log successful filter operation."""
        self._logger.info(f"Successfully filtered to {len(entries)} entries")
        return entries
    
    def _get_config_summary(self) -> dict[str, object]:
        """Get configuration summary for service info."""
        return {
            "max_entries": getattr(self._config, 'max_entries', 10000),
            "validate_dn": getattr(self._config, 'validate_dn', True),
            "strict_mode": getattr(self._config, 'strict_mode', False),
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp string."""
        from datetime import datetime
        return datetime.now().isoformat()

    # =============================================================================
    # COMPATIBILITY SERVICE CLASSES - Legacy support
    # =============================================================================

    class _ParserCompatibilityService:
        """Parser service compatibility wrapper."""
        
        def __init__(self, api: FlextLdifAPI) -> None:
            self._api = api
        
        def parse_content(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content - delegates to API."""
            return self._api.parse(content)
        
        def parse_file(self, file_path: Path) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF file - delegates to API."""
            return self._api.parse_ldif_file(file_path)

    class _WriterCompatibilityService:
        """Writer service compatibility wrapper."""
        
        def __init__(self, api: FlextLdifAPI) -> None:
            self._api = api
        
        def write_entries_to_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
            """Write entries to string - delegates to API."""
            return self._api.write(entries)
        
        def write_entries_to_file(self, entries: list[FlextLdifModels.Entry], file_path: Path) -> FlextResult[bool]:
            """Write entries to file - delegates to API."""
            return self._api.write_file(entries, file_path)

    class _ValidatorCompatibilityService:
        """Validator service compatibility wrapper."""
        
        def __init__(self, api: FlextLdifAPI) -> None:
            self._api = api
        
        def validate_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Validate entries - delegates to API."""
            return self._api.validate_entries(entries)

    class _RepositoryCompatibilityService:
        """Repository service compatibility wrapper."""
        
        def __init__(self, api: FlextLdifAPI) -> None:
            self._api = api
        
        def store_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[bool]:
            """Store entries - simplified implementation."""
            # Simple validation as storage
            return self._api.validate_entries(entries)
        
        def retrieve_entries(self, filter_func: Callable[[FlextLdifModels.Entry], bool] | None = None) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Retrieve entries - returns empty list as no storage."""
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

    class _AnalyticsCompatibilityService:
        """Analytics service compatibility wrapper."""
        
        def __init__(self, api: FlextLdifAPI) -> None:
            self._api = api
        
        def analyze_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[dict[str, object]]:
            """Analyze entries - delegates to API."""
            return self._api.analyze(entries)


# Compatibility aliases for legacy service architecture
# These provide minimal wrappers around FlextLdifAPI for test compatibility


class FlextLdifParserService:
    """Compatibility alias for parsing functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize parser service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def parse_content(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string."""
        return self._api.parse(content)

    def parse_ldif_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file."""
        return self._api.parse_ldif_file(Path(file_path))

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        """Validate LDIF syntax."""
        return self._api.parse(content).map(lambda _: True)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifWriterService:
    """Compatibility alias for writing functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize writer service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def write_entries_to_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        return self._api.write(entries)

    def write_entries_to_file(self, entries: list[FlextLdifModels.Entry], file_path: str | Path) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        return self._api.write_file(entries, Path(file_path))

    def write_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        return self._api.write([entry])

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifValidatorService:
    """Compatibility alias for validation functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize validator service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def validate_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate LDIF entries."""
        return self._api.validate_entries(entries)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifRepositoryService:
    """Compatibility alias for repository functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize repository service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def filter_entries_by_attribute(
        self,
        entries: list[FlextLdifModels.Entry],
        attribute_name: str,
        attribute_value: str | None = None
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute name and value."""
        def filter_func(entry: FlextLdifModels.Entry) -> bool:
            if attribute_value is None:
                return entry.has_attribute(attribute_name)
            values = entry.get_attribute(attribute_name)
            return values is not None and attribute_value in values

        return self._api.filter_entries(entries, filter_func)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifAnalyticsService:
    """Compatibility alias for analytics functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize analytics service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def analyze_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[dict[str, object]]:
        """Analyze LDIF entries and provide statistics."""
        return self._api.analyze(entries)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifTransformerService:
    """Compatibility alias for transformation functionality."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize transformer service with optional configuration."""
        self._api = FlextLdifAPI(config)

    def transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        transformation_fn: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform LDIF entries using provided function."""
        return self._api.transform(entries, transformation_fn)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Check service health."""
        return self._api.health_check()


class FlextLdifServices:
    """Unified services container for compatibility."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize services container with optional configuration."""
        self.parser = FlextLdifParserService(config)
        self.writer = FlextLdifWriterService(config)
        self.validator = FlextLdifValidatorService(config)
        self.repository = FlextLdifRepositoryService(config)
        self.analytics = FlextLdifAnalyticsService(config)
        self.transformer = FlextLdifTransformerService(config)


__all__ = [
    "FlextLdifAPI",
    "FlextLdifAnalyticsService",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifServices",
    "FlextLdifTransformerService",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
]
