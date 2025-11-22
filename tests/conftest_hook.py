"""Pytest hooks for LDAP failure detection and dirty marking (REGRA 4).

This module implements the pytest hook to detect LDAP service failures
and mark containers dirty for recreation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator
from typing import cast

import pytest

# LDAP failure patterns that indicate container corruption (REGRA 4)
LDAP_FAILURE_PATTERNS = [
    "Can't contact LDAP server",
    "Connection refused",
    "LDAP server is unavailable",
    "LDAP server not available",
    "Invalid credentials",
    "ldap.SERVER_DOWN",
    "Connection reset by peer",
    "Timeout",
    "UNAVAILABLE",
    "ldap3.core.exceptions",
]


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo[object],
) -> Generator[object]:
    """Detect LDAP failures and mark container dirty (REGRA 4).

    Examines test failures and identifies LDAP service failures vs test logic failures.

    Marks container dirty when:
    - LDAP connection failures occur
    - LDAP server errors occur
    - Container health check failures

    Does NOT mark dirty when:
    - Assertion errors (test logic)
    - Validation errors (business logic)
    - Expected exceptions (test expectations)

    Args:
        item: Test item being executed
        call: Call information

    """
    outcome = yield
    # Type narrowing: outcome from hookwrapper has get_result() method
    # Use getattr to safely access get_result and cast the result
    get_result_method = getattr(outcome, "get_result", None)
    if get_result_method is None:
        return
    report = cast("pytest.TestReport", get_result_method())

    # Only process failures during test execution (not setup/teardown)
    if report.when != "call" or not report.failed:
        return

    # Check if test uses ldap_container fixture
    # Type narrowing: item has fixturenames attribute for Function/Class items
    fixturenames = getattr(item, "fixturenames", None)
    if fixturenames is None or "ldap_container" not in fixturenames:
        return

    # Get exception information
    if call.excinfo is None:
        return

    exception_message = str(call.excinfo.value)

    # Check if this is an LDAP service failure (not test logic)
    is_ldap_failure = any(
        pattern.lower() in exception_message.lower()
        for pattern in LDAP_FAILURE_PATTERNS
    )

    if not is_ldap_failure:
        return  # Test logic failure - do NOT mark dirty

    # LDAP service failure detected - mark container dirty
    try:
        # Get docker_control from session fixtures (FlextTestDocker)
        docker_control = item.session._fixturemanager._arg2fixturedefs.get(
            "docker_control",
        )

        if docker_control and len(docker_control) > 0:
            # Get the actual fixture value
            fixture_def = docker_control[0]
            if (
                hasattr(fixture_def, "cached_result")
                and fixture_def.cached_result
                and len(fixture_def.cached_result) > 0
            ):
                docker_instance = fixture_def.cached_result[0]

                if docker_instance is not None:
                    # Mark container dirty
                    container_name = "flext-openldap-test"
                    mark_result = docker_instance.mark_container_dirty(container_name)

                    if mark_result.is_success:
                        # Add section to test report
                        report.sections.append(
                            (
                                "⚠️  LDAP SERVICE FAILURE DETECTED",
                                f"Container '{container_name}' marked DIRTY for recreation.\n"
                                f"Error: {exception_message}\n"
                                f"Next test run will recreate the container.",
                            ),
                        )

                        # Log warning
                        if hasattr(docker_instance, "logger"):
                            docker_instance.logger.warning(
                                "Container marked dirty due to LDAP failure",
                                extra={
                                    "container": container_name,
                                    "test": item.nodeid,
                                    "error": exception_message[:200],
                                },
                            )
                    else:
                        # Failed to mark dirty - log error
                        report.sections.append(
                            (
                                "⚠️  LDAP FAILURE WARNING",
                                (
                                    f"LDAP failure detected but failed to mark container dirty:\n"
                                    f"{mark_result.error}"
                                ),
                            ),
                        )

    except Exception as e:
        # Failed to access docker_control - log but don't fail test
        report.sections.append(
            (
                "⚠️  DIRTY MARKING ERROR",
                f"LDAP failure detected but failed to mark container dirty:\n{e}",
            ),
        )
