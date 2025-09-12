#!/usr/bin/env python3
"""Example: Using FlextLDIFConfig for LDIF-specific configuration.

This example demonstrates how to use FlextLDIFConfig as a singleton
for LDIF-specific configuration management, extending flext-core FlextConfig.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import FlextLDIFAPI, initialize_ldif_config
from flext_ldif.config import get_ldif_config


def main() -> None:
    """Demonstrate LDIF configuration usage."""
    print("=== FLEXT-LDIF Configuration Example ===\n")

    # Initialize LDIF configuration with custom parameters
    print("1. Initializing LDIF configuration...")
    config_result = initialize_ldif_config(
        ldif_max_entries=50000,
        ldif_strict_validation=True,
        ldif_parallel_processing=True,
        ldif_max_workers=8,
        ldif_enable_analytics=True,
    )

    if config_result.is_failure:
        print(f"❌ Configuration initialization failed: {config_result.error}")
        return

    print("✅ LDIF configuration initialized successfully")

    # Get global configuration instance
    print("\n2. Accessing global configuration...")
    config = get_ldif_config()

    # Display configuration values
    print(f"   Max entries: {config.ldif_max_entries}")
    print(f"   Strict validation: {config.ldif_strict_validation}")
    print(f"   Parallel processing: {config.ldif_parallel_processing}")
    print(f"   Max workers: {config.ldif_max_workers}")
    print(f"   Analytics enabled: {config.ldif_enable_analytics}")

    # Get configuration dictionaries
    print("\n3. Getting configuration dictionaries...")
    processing_config = config.get_ldif_processing_config()
    validation_config = config.get_ldif_validation_config()
    analytics_config = config.get_ldif_analytics_config()

    print("   Processing config:", processing_config)
    print("   Validation config:", validation_config)
    print("   Analytics config:", analytics_config)

    # Validate business rules
    print("\n4. Validating business rules...")
    validation_result = config.validate_ldif_business_rules()
    if validation_result.is_success:
        print("✅ Business rules validation passed")
    else:
        print(f"❌ Business rules validation failed: {validation_result.error}")

    # Apply configuration overrides
    print("\n5. Applying configuration overrides...")
    overrides = {
        "ldif_max_entries": 100000,
        "ldif_chunk_size": 2000,
        "ldif_analytics_cache_size": 20000,
    }

    override_result = config.apply_ldif_overrides(overrides)
    if override_result.is_success:
        print("✅ Configuration overrides applied successfully")
        print(f"   New max entries: {config.ldif_max_entries}")
        print(f"   New chunk size: {config.ldif_chunk_size}")
        print(f"   New cache size: {config.ldif_analytics_cache_size}")
    else:
        print(f"❌ Configuration override failed: {override_result.error}")

    # Use configuration in LDIF operations
    print("\n6. Using configuration in LDIF operations...")
    api = FlextLDIFAPI()

    # Create sample LDIF content
    sample_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
sn: TestUser

dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
cn: REDACTED_LDAP_BIND_PASSWORD
objectClass: person
sn: AdminUser
"""

    # Write to temporary file
    with tempfile.NamedTemporaryFile(encoding="utf-8", mode="w", suffix=".ldif", delete=False) as f:
        f.write(sample_ldif)
        temp_path = Path(f.name)

    try:
        # Parse LDIF using configuration
        parse_result = api.parse_file(temp_path)
        if parse_result.is_success:
            entries = parse_result.unwrap()
            print(f"✅ Parsed {len(entries)} entries successfully")

            # Validate entries using configuration
            validate_result = api.validate(entries)
            if validate_result.is_success:
                print("✅ Entry validation passed")
            else:
                print(f"❌ Entry validation failed: {validate_result.error}")

            # Analyze entries if analytics is enabled
            if config.ldif_enable_analytics:
                analyze_result = api.analyze(entries)
                if analyze_result.is_success:
                    stats = analyze_result.unwrap()
                    print(f"✅ Analytics completed: {stats}")
                else:
                    print(f"❌ Analytics failed: {analyze_result.error}")
        else:
            print(f"❌ LDIF parsing failed: {parse_result.error}")

    finally:
        # Clean up temporary file
        temp_path.unlink(missing_ok=True)

    # Demonstrate configuration inheritance from flext-core
    print("\n7. Demonstrating flext-core inheritance...")
    print(f"   Base URL: {config.base_url}")
    print(f"   Debug mode: {config.debug}")
    print(f"   Log level: {config.log_level}")
    print(f"   Max workers: {config.max_workers}")

    # Show feature flags
    feature_flags = config.get_feature_flags()
    print(f"   Feature flags: {feature_flags}")

    print("\n=== Configuration Example Complete ===")


if __name__ == "__main__":
    main()
