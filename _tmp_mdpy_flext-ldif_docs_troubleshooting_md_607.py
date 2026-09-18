# from flext-ldif_docs/troubleshooting.md:607
from __future__ import annotations


def generate_support_info() -> t.JsonMapping:
    """Generate information for support requests."""
    import sys
    import platform
    from flext_ldif import __version__ as ldif_version

    return {
        "flext_ldif_version": ldif_version,
        "python_version": sys.version,
        "platform": platform.platform(),
        "health_check": run_health_check(),
        "reproduction_steps": "Include steps to reproduce the issue",
        "expected_behavior": "Describe expected behavior",
        "actual_behavior": "Describe actual behavior",
    }```
### Emergency Contacts

For critical production issues:

1. Check health status: `run_health_check()`
1. Review logs for error patterns
1. Attempt with debug configuration
1. Document issue with support information
1. Contact FLEXT support team with detailed report

______________________________________________________________________

This troubleshooting guide provides comprehensive solutions for common FLEXT-LDIF issues while maintaining integration with FLEXT ecosystem support patterns.
