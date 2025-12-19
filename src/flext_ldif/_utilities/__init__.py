"""FLEXT LDIF Utilities - Internal package exports.

This module exports all internal utility classes and functions.
All implementations are in their respective modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# FlextLdifUtilities moved to avoid circular import - import from utilities.py directly when needed
# Type aliases using string literals to break circular import
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.builders import (
    FilterConfigBuilder,
    ProcessConfigBuilder,
    TransformConfigBuilder,
    WriteConfigBuilder,
)
from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.filters import (
    AndFilter,
    ByAttrsFilter,
    ByAttrValueFilter,
    ByDnFilter,
    ByDnUnderBaseFilter,
    ByObjectClassFilter,
    CustomFilter,
    EntryFilter,
    ExcludeAttrsFilter,
    Filter,
    IsSchemaEntryFilter,
    NotFilter,
    OrFilter,
)
from flext_ldif._utilities.fluent import DnOps, EntryOps
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
from flext_ldif._utilities.pipeline import (
    Pipeline,
    PipelineStep,
    ProcessingPipeline,
    ValidationPipeline,
    ValidationResult,
)
from flext_ldif._utilities.result import FlextLdifResult
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif._utilities.transformers import (
    ConvertBooleansTransformer,
    CustomTransformer,
    EntryTransformer,
    FilterAttrsTransformer,
    Normalize,
    NormalizeAttrsTransformer,
    NormalizeDnTransformer,
    RemoveAttrsTransformer,
    ReplaceBaseDnTransformer,
    Transform,
)
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters
from flext_ldif.constants import c
from flext_ldif.typings import t

# Type alias using forward reference to break circular import
# Cannot import FlextLdifModelsDomains at module level due to circular dependency
# Use protocol-based type from typings instead
# Entry: TypeAlias = t.Entry  # REMOVED: Use t.Entry directly (no redundant aliases for nested objects)

__all__ = [
    "AndFilter",
    "ByAttrValueFilter",
    "ByAttrsFilter",
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    "ByObjectClassFilter",
    "ConvertBooleansTransformer",
    "CustomFilter",
    "CustomTransformer",
    "DnOps",
    "EntryFilter",
    "EntryOps",
    "EntryTransformer",
    "ExcludeAttrsFilter",
    "Filter",
    "FilterAttrsTransformer",
    "FilterConfigBuilder",
    "FlextLdifResult",
    # FlextLdifUtilities removed - import from flext_ldif.utilities directly to avoid circular import
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDecorators",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "IsSchemaEntryFilter",
    "Normalize",
    "NormalizeAttrsTransformer",
    "NormalizeDnTransformer",
    "NotFilter",
    "OrFilter",
    "Pipeline",
    "PipelineStep",
    "ProcessConfigBuilder",
    "ProcessingPipeline",
    "RemoveAttrsTransformer",
    "ReplaceBaseDnTransformer",
    "Transform",
    "TransformConfigBuilder",
    "ValidationPipeline",
    "ValidationResult",
    "WriteConfigBuilder",
    "c",
    "t",
]
