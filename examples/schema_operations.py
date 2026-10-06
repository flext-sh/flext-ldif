"""Example 5: Advanced Schema Operations - Parallel Processing and Validation.

Thin facade over the focused schema-operation example modules:
``schema_building`` (intelligent building), ``schema_validation`` (parallel
validation), ``schema_migration`` (migration pipeline), ``schema_batches``
(batch operations), and ``schema_pipeline`` (railway pipeline).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from examples.schema_batches import batch_schema_operations
from examples.schema_building import intelligent_schema_building
from examples.schema_migration import schema_migration_pipeline
from examples.schema_pipeline import railway_schema_pipeline
from examples.schema_validation import parallel_schema_validation

__all__: tuple[str, ...] = (
    "batch_schema_operations",
    "intelligent_schema_building",
    "parallel_schema_validation",
    "railway_schema_pipeline",
    "schema_migration_pipeline",
)
