# from flext-ldif/docs/troubleshooting.md:212
from __future__ import annotations

from flext_ldif import ldif, FlextLdifModels, p, r


def handle_validation_errors(entries: list) -> p.Result[list]:
    """Handle validation errors with detailed reporting."""
    # Try with strict validation first
    strict_config = FlextLdifModels.Config(strict_validation=True)
    strict_api = ldif(settings=strict_config)

    strict_result = strict_api.validate_entries(entries)
    if strict_result.success:
        u.Cli.print("✓ All entries pass strict validation")
        return r[list].ok(entries)

    u.Cli.print(f"✗ Strict validation failed: {strict_result.error}")

    # Try with permissive validation
    permissive_config = FlextLdifModels.Config(
        strict_validation=False, ignore_unknown_attributes=True
    )
    permissive_api = ldif(settings=permissive_config)

    permissive_result = permissive_api.validate_entries(entries)
    if permissive_result.success:
        u.Cli.print("✓ Entries pass permissive validation")
        u.Cli.print("⚠️  Consider reviewing data quality")
        return r[list].ok(entries)

    return r[list].fail(f"Validation failed: {permissive_result.error}")


def analyze_entry_issues(entries: list) -> None:
    """Analyze common entry validation issues."""
    for i, entry in enumerate(entries):
        u.Cli.print(f"\nEntry {i + 1}: {entry.dn}")

        # Check DN format
        if not entry.dn or "=" not in entry.dn:
            u.Cli.print("  ❌ Invalid DN format")

        # Check object classes
        object_classes = entry.get_object_classes()
        if not object_classes:
            u.Cli.print("  ❌ Missing object class")

        # Check required attributes for person entries
        if "person" in object_classes:
            if not entry.get_attribute_values("cn"):
                u.Cli.print("  ❌ Person missing required 'cn' attribute")
            if not entry.get_attribute_values("sn"):
                u.Cli.print("  ❌ Person missing required 'sn' attribute")

        # Check for empty attributes
        for attr_name, attr_values in entry.attributes.items():
            if not attr_values or any(not v.strip() for v in attr_values):
                u.Cli.print(f"  ⚠️  Empty values in attribute '{attr_name}'")```
### Performance Issues

#### Slow Processing

**Symptom**: LDIF processing takes significantly longer than expected.

**Diagnosis**:

