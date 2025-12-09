"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldif/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.models import FlextTestsModels

from flext_ldif.models import FlextLdifModels


class TestsFlextLdifModels(FlextTestsModels, FlextLdifModels):
    """Test models extending FlextTestsModels and FlextLdifModels.

    Provides test-specific model extensions without duplicating parent functionality.
    All parent models are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'm' for convenient access in tests.
    """

    # Test-specific model extensions can be added here
    # All parent models (Entry, SchemaEventConfig, etc.) are accessible via inheritance


__all__ = [
    "TestsFlextLdifModels",
]
