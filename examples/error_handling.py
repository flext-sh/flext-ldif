#!/usr/bin/env python3
"""Error handling example.

Demonstrates FlextResult patterns and comprehensive error handling
using Clean Architecture principles and flext-core integration.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import get_logger
from flext_ldif import (
    FlextLdifAPI,
    FlextLdifConfig,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)


def demonstrate_result_patterns() -> None:
    """Demonstrate FlextResult success and failure patterns."""
    print("🔄 FlextResult Pattern Demonstration")
    print("-" * 40)
    
    api = FlextLdifAPI()
    
    # Success case
    valid_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
    
    result = api.parse(valid_ldif)
    if result.is_success:
        print(f"✅ Success: Parsed {len(result.data or [])} entries")
    else:
        print(f"❌ Unexpected failure: {result.error}")
    
    # Failure case - invalid LDIF
    invalid_ldif = """invalid ldif format
without proper structure
"""
    
    result = api.parse(invalid_ldif)
    if result.is_success:
        print(f"⚠️  Unexpected success with invalid LDIF")
    else:
        print(f"✅ Expected failure: {result.error}")
    
    # Chaining results
    print("\n🔗 Result chaining demonstration:")
    
    def process_ldif_chain(ldif_content: str) -> str:
        """Demonstrate result chaining pattern."""
        # Parse
        parse_result = api.parse(ldif_content)
        if not parse_result.is_success:
            return f"Parse failed: {parse_result.error}"
        
        entries = parse_result.data
        if not entries:
            return "No entries found"
        
        # Validate
        validation_errors = []
        for entry in entries:
            validation_result = entry.validate_domain_rules()
            if not validation_result.is_success:
                validation_errors.append(validation_result.error)
        
        if validation_errors:
            return f"Validation failed: {', '.join(validation_errors)}"
        
        # Filter
        filter_result = api.filter_persons(entries)
        if not filter_result.is_success:
            return f"Filter failed: {filter_result.error}"
        
        if filter_result.data is None:
            return "Filter returned no data"
        
        return f"Successfully processed {len(filter_result.data)} person entries"
    
    # Test with valid LDIF
    result_msg = process_ldif_chain(valid_ldif)
    print(f"  Valid LDIF: {result_msg}")
    
    # Test with invalid LDIF
    result_msg = process_ldif_chain(invalid_ldif)
    print(f"  Invalid LDIF: {result_msg}")


def demonstrate_exception_handling() -> None:
    """Demonstrate proper exception handling patterns."""
    print("\n⚠️  Exception Handling Demonstration")
    print("-" * 40)
    
    logger = get_logger(__name__)
    
    # Test different exception types
    try:
        # This will raise FlextLdifParseError
        raise FlextLdifParseError("Test parse error", line_number=42)
        
    except FlextLdifParseError as e:
        print(f"✅ Caught FlextLdifParseError: {e}")
        print(f"   Line number: {e.line_number}")
        logger.error("Parse error occurred", exc_info=True)
    
    try:
        # This will raise FlextLdifValidationError
        raise FlextLdifValidationError(
            "Test validation error",
            validation_details={"field": "dn", "issue": "empty"}
        )
        
    except FlextLdifValidationError as e:
        print(f"✅ Caught FlextLdifValidationError: {e}")
        print(f"   Validation details: {e.validation_details}")
        logger.error("Validation error occurred", exc_info=True)
    
    try:
        # This will raise base FlextLdifError
        raise FlextLdifError("Test base error")
        
    except FlextLdifError as e:
        print(f"✅ Caught FlextLdifError: {e}")
        logger.error("LDIF error occurred", exc_info=True)


def demonstrate_file_error_handling() -> None:
    """Demonstrate file operation error handling."""
    print("\n📁 File Error Handling Demonstration")
    print("-" * 40)
    
    api = FlextLdifAPI()
    
    # Test with non-existent file
    nonexistent_file = Path("/nonexistent/path/file.ldif")
    result = api.parse_file(nonexistent_file)
    
    if result.is_success:
        print("⚠️  Unexpected success with non-existent file")
    else:
        print(f"✅ Expected file error: {result.error}")
    
    # Test with directory instead of file
    directory_path = Path(__file__).parent
    result = api.parse_file(directory_path)
    
    if result.is_success:
        print("⚠️  Unexpected success with directory")
    else:
        print(f"✅ Expected directory error: {result.error}")
    
    # Test with permission issues (simulate)
    print("📝 Simulating permission errors...")
    
    # Create a temporary file
    temp_file = Path(__file__).parent / "temp_test.ldif"
    temp_file.write_text("dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n")
    
    try:
        # Try to parse valid file
        result = api.parse_file(temp_file)
        if result.is_success:
            print(f"✅ Successfully parsed temporary file: {len(result.data or [])} entries")
        else:
            print(f"❌ Failed to parse temporary file: {result.error}")
        
        # Try to write to read-only location (will likely fail)
        if result.is_success and result.data:
            readonly_path = Path("/readonly/output.ldif")  # This will fail
            write_result = api.write(result.data, readonly_path)
            
            if write_result.is_success:
                print("⚠️  Unexpected write success to read-only location")
            else:
                print(f"✅ Expected write error: {write_result.error}")
    
    finally:
        # Clean up
        if temp_file.exists():
            temp_file.unlink()


def demonstrate_configuration_error_handling() -> None:
    """Demonstrate configuration error handling."""
    print("\n⚙️  Configuration Error Handling")
    print("-" * 40)
    
    # Test with extreme configurations
    try:
        # Very low max_entries
        config = FlextLdifConfig(max_entries=0)
        api = FlextLdifAPI(config)
        
        sample_file = Path(__file__).parent / "sample_basic.ldif"
        if sample_file.exists():
            result = api.parse_file(sample_file)
            if result.is_success:
                print("⚠️  Parsed successfully with max_entries=0")
            else:
                print(f"✅ Expected max_entries error: {result.error}")
    
    except Exception as e:
        print(f"✅ Configuration validation error: {e}")
    
    # Test with strict validation
    config = FlextLdifConfig(strict_validation=True, allow_empty_attributes=False)
    api = FlextLdifAPI(config)
    
    # Create LDIF with empty attributes
    empty_attr_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: 
"""
    
    result = api.parse(empty_attr_ldif)
    if result.is_success and result.data:
        print("✅ Parsed LDIF with empty attributes")
        
        # Test validation
        for entry in result.data:
            validation_result = entry.validate_domain_rules()
            if validation_result.is_success:
                print("  ✅ Entry validation passed")
            else:
                print(f"  ⚠️  Entry validation warning: {validation_result.error}")
    else:
        print(f"❌ Failed to parse LDIF with empty attributes: {result.error}")


def main() -> None:
    """Demonstrate comprehensive error handling patterns."""
    print("🚨 FLEXT LDIF Error Handling Example")
    print("=" * 50)
    
    # Set up logging
    logger = get_logger(__name__)
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
        
        print("\n🏆 Error Handling Summary:")
        print("  ✅ FlextResult success/failure patterns")
        print("  ✅ Result chaining and composition")
        print("  ✅ Exception hierarchy handling")
        print("  ✅ File operation error handling")
        print("  ✅ Configuration validation")
        print("  ✅ Structured logging integration")
        
        logger.info("Error handling demonstration completed successfully")
        
    except Exception as e:
        print(f"\n💥 Unexpected error in demonstration: {e}")
        logger.error("Demonstration failed", exc_info=True)
        raise
    
    print("\n🎉 Error handling example completed!")


if __name__ == "__main__":
    main()