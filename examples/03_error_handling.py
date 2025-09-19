#!/usr/bin/env python3
"""Error handling example.

Demonstrates FlextResult patterns and comprehensive error handling
using Clean Architecture principles and flext-core integration.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextTypes
from flext_ldif import (
    FlextLdifAPI,
    FlextLdifExceptions,
    FlextLdifModels,
)
from flext_ldif.config import FlextLdifConfig


# SOLID REFACTORING: Strategy Pattern to reduce complexity from 11 to 4
class ResultPatternDemonstrator:
    """Strategy Pattern for FlextResult demonstration.

    SOLID REFACTORING: Reduces complexity by organizing result patterns into strategies
    with single responsibility per pattern type.
    """

    def __init__(self) -> None:
        """Initialize result pattern demonstrator."""
        self.api = FlextLdifAPI()
        self.valid_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        self.invalid_ldif = """invalid ldif format
without proper structure
"""

    def demonstrate_all_patterns(self) -> None:
        """Template method: demonstrate all FlextResult patterns."""
        self._demonstrate_success_pattern()
        self._demonstrate_failure_pattern()
        self._demonstrate_chaining_pattern()

    def _demonstrate_success_pattern(self) -> None:
        """Demonstrate FlextResult success patterns."""
        result = self.api.parse(self.valid_ldif)
        if result.is_success:
            pass  # Success case handled

    def _demonstrate_failure_pattern(self) -> None:
        """Demonstrate FlextResult failure patterns."""
        result = self.api.parse(self.invalid_ldif)
        if result.is_success:
            pass  # Failure case handled

    def _demonstrate_chaining_pattern(self) -> None:
        """Demonstrate result chaining patterns."""
        # Test with valid LDIF
        self._process_ldif_chain(self.valid_ldif)

        # Test with invalid LDIF
        self._process_ldif_chain(self.invalid_ldif)

    def _process_ldif_chain(self, ldif_content: str) -> str:
        """Demonstrate result chaining pattern."""
        # Parse
        parse_result = self.api.parse(ldif_content)
        if not parse_result.is_success:
            return f"Parse failed: {parse_result.error}"

        entries = parse_result.value
        if not entries:
            return "No entries found"

        # Validate
        validation_errors = self._validate_entries(entries)
        if validation_errors:
            return f"Validation failed: {', '.join(validation_errors)}"

        # Filter
        filter_result = self.api.filter_persons(entries)
        if not filter_result.is_success:
            return f"Filter failed: {filter_result.error}"

        filtered_entries = filter_result.unwrap_or([])
        if not filtered_entries:
            return "Filter returned no data"

        return f"Successfully processed {len(filtered_entries)} person entries"

    def _validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextTypes.Core.StringList:
        """Validate entries and return errors."""
        validation_errors: FlextTypes.Core.StringList = []
        for entry in entries:
            # Use FlextResult pattern instead of exceptions
            if hasattr(entry, "validate_business_rules"):
                validation_result = entry.validate_business_rules()
                if validation_result.is_failure:
                    validation_errors.append(
                        validation_result.error or "Validation failed",
                    )
        return validation_errors


def demonstrate_result_patterns() -> None:
    """Demonstrate FlextResult success and failure patterns using Strategy Pattern.

    SOLID REFACTORING: Reduced complexity from 11 to 4 using Strategy Pattern.
    """
    demonstrator = ResultPatternDemonstrator()
    demonstrator.demonstrate_all_patterns()


def demonstrate_exception_handling() -> None:
    """Demonstrate proper exception handling patterns."""
    logger = FlextLogger(__name__)

    # Test different error types using FlextResult patterns
    def _test_parse_error() -> FlextResult[None]:
        msg = "Test parse error"
        return FlextLdifExceptions.parse_error(msg, line_number=42)

    parse_result = _test_parse_error()
    if parse_result.is_failure:
        logger.error(f"Parse error occurred: {parse_result.error}")

    def _test_validation_error() -> FlextResult[None]:
        msg = "Test validation error"
        return FlextLdifExceptions.validation_error(
            msg,
            dn="cn=test,dc=example,dc=com",
            validation_rule="empty field",
        )

    validation_result = _test_validation_error()
    if validation_result.is_failure:
        logger.error(f"Validation error occurred: {validation_result.error}")

    def _test_base_error() -> FlextResult[None]:
        msg = "Test base error"
        return FlextLdifExceptions.error(msg)

    base_result = _test_base_error()
    if base_result.is_failure:
        logger.error(f"LDIF error occurred: {base_result.error}")


def demonstrate_file_error_handling() -> None:
    """Demonstrate file operation error handling."""
    api = FlextLdifAPI()

    # Test with non-existent file
    nonexistent_file = Path("/nonexistent/path/file.ldif")
    result = api.parse_file(nonexistent_file)

    if result.is_success:
        pass

    # Test with directory instead of file
    directory_path = Path(__file__).parent
    result = api.parse_file(directory_path)

    if result.is_success:
        pass

    # Test with permission issues (simulate)

    # Create a temporary file
    temp_file = Path(__file__).parent / "temp_test.ldif"
    temp_file.write_text(
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
    )

    try:
        # Try to parse valid file
        result = api.parse_file(temp_file)
        if result.is_success:
            pass

        # Try to write to read-only location (will likely fail)
        entries = result.unwrap_or([])
        if entries:
            readonly_path = Path("/readonly/output.ldif")  # This will fail
            write_result = api.write_file(entries, str(readonly_path))

            if write_result.is_success:
                pass

    finally:
        # Clean up
        if temp_file.exists():
            temp_file.unlink()


def demonstrate_configuration_error_handling() -> None:
    """Demonstrate configuration error handling."""
    # Test with extreme configurations
    try:
        # Very low max_entries
        config = FlextLdifConfig(ldif_max_entries=0)
        api = FlextLdifAPI(config)

        sample_file = Path(__file__).parent / "sample_basic.ldif"
        if sample_file.exists():
            result = api.parse_file(sample_file)
            if result.is_success:
                pass

    except Exception as exc:  # Log instead of bare pass
        logger = FlextLogger(__name__)
        logger.exception("Configuration test failed", exc_info=exc)

    # Test with strict validation
    config = FlextLdifConfig(ldif_strict_validation=True, ldif_allow_empty_values=False)
    api = FlextLdifAPI(config)

    # Create LDIF with empty attributes
    empty_attr_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:
"""

    result = api.parse(empty_attr_ldif)
    entries = result.unwrap_or([])
    if entries:
        # Test validation using FlextResult pattern
        for entry in entries:
            if hasattr(entry, "validate_business_rules"):
                validation_result = entry.validate_business_rules()
                if validation_result.is_failure:
                    # Silently skip validation failures for demonstration
                    pass


def main() -> None:
    """Demonstrate comprehensive error handling patterns."""
    # Set up logging
    logger = FlextLogger(__name__)
    logger.info("Starting error handling demonstration")

    try:
        # FlextResult patterns
        demonstrate_result_patterns()

        # Exception handling
        demonstrate_exception_handling()

        # File error handling
        demonstrate_file_error_handling()

        # Configuration error handling
        demonstrate_configuration_error_handling()

        logger.info("Error handling demonstration completed successfully")

    except Exception:
        logger.exception("Demonstration failed")
        raise


if __name__ == "__main__":
    main()
