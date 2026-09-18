# from flext-ldif/docs/troubleshooting.md:476
from __future__ import annotations


def run_health_check() -> t.JsonMapping:
    """Run comprehensive health check for FLEXT-LDIF."""
    results = {"status": "healthy", "checks": {}, "warnings": [], "errors": []}

    # Check imports
    try:
        from flext_ldif import ldif, FlextLdifModels

        results["checks"]["imports"] = "✓ All imports successful"
    except ImportError as e:
        results["checks"]["imports"] = f"❌ Import failed: {e}"
        results["status"] = "unhealthy"
        results["errors"].append(f"Import error: {e}")

    # Check API initialization
    try:
        api = ldif()
        results["checks"]["api_init"] = "✓ API initializes successfully"
    except Exception as e:
        results["checks"]["api_init"] = f"❌ API initialization failed: {e}"
        results["status"] = "unhealthy"
        results["errors"].append(f"API initialization error: {e}")

    # Check basic functionality
    try:
        test_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        parse_result = api.parse_string(test_ldif)
        if parse_result.success:
            results["checks"]["basic_parsing"] = "✓ Basic parsing works"
        else:
            results["checks"]["basic_parsing"] = (
                f"⚠️ Basic parsing issue: {parse_result.error}"
            )
            results["warnings"].append(f"Basic parsing issue: {parse_result.error}")
    except Exception as e:
        results["checks"]["basic_parsing"] = f"❌ Basic parsing failed: {e}"
        results["errors"].append(f"Basic parsing error: {e}")

    # Check container integration
    try:
        container = FlextContainer.get_global()
        reg_result = container.bind("health_check_api", api)
        if reg_result.success:
            results["checks"]["container_integration"] = "✓ Container integration works"
        else:
            results["checks"]["container_integration"] = (
                f"⚠️ Container issue: {reg_result.error}"
            )
            results["warnings"].append(
                f"Container integration issue: {reg_result.error}"
            )
    except Exception as e:
        results["checks"]["container_integration"] = (
            f"❌ Container integration failed: {e}"
        )
        results["errors"].append(f"Container integration error: {e}")

    return results


def print_health_check_report() -> None:
    """Print formatted health check report."""
    results = run_health_check()

    u.Cli.print("=== FLEXT-LDIF Health Check ===")
    u.Cli.print(f"Overall Status: {results['status'].upper()}")
    u.Cli.print()

    u.Cli.print("Checks:")
    for check, result in results["checks"].items():
        u.Cli.print(f"  {check}: {result}")

    if results["warnings"]:
        u.Cli.print("\nWarnings:")
        for warning in results["warnings"]:
            u.Cli.print(f"  ⚠️ {warning}")

    if results["errors"]:
        u.Cli.print("\nErrors:")
        for error in results["errors"]:
            u.Cli.print(f"  ❌ {error}")

    u.Cli.print()
    u.Cli.print("For additional help, see: docs/troubleshooting.md")```
### Debug Mode Configuration

