"""Configuration model aliases for flext-ldif utilities.

Canonical definitions live in flext_ldif._models.settings.FlextLdifModelsSettings.
This module provides backward-compatible aliases for existing consumers.
"""

from __future__ import annotations

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c

CaseFoldOption = c.Ldif.CaseFoldOption
SpaceHandlingOption = c.Ldif.SpaceHandlingOption
EscapeHandlingOption = c.Ldif.EscapeHandlingOption

MetadataPreserveConfig = FlextLdifModelsSettings.MetadataPreserveConfig

DnNormalizationConfig = FlextLdifModelsSettings.DnNormalizationConfig
AttrNormalizationConfig = FlextLdifModelsSettings.AttrNormalizationConfig
AclConversionConfig = FlextLdifModelsSettings.AclConversionConfig
MetadataConfig = FlextLdifModelsSettings.MetadataConfig
ValidationConfig = FlextLdifModelsSettings.UtilValidationConfig
FilterConfig = FlextLdifModelsSettings.UtilFilterConfig
ProcessConfig = FlextLdifModelsSettings.UtilProcessConfig
TransformConfig = FlextLdifModelsSettings.UtilTransformConfig
WriteConfig = FlextLdifModelsSettings.UtilWriteConfig
LoadConfig = FlextLdifModelsSettings.LoadConfig
SchemaParseConfig = FlextLdifModelsSettings.SchemaParseConfig
ValidationRuleSet = FlextLdifModelsSettings.ValidationRuleSet

__all__: list[str] = [
    "AclConversionConfig",
    "AttrNormalizationConfig",
    "CaseFoldOption",
    "DnNormalizationConfig",
    "EscapeHandlingOption",
    "FilterConfig",
    "LoadConfig",
    "MetadataConfig",
    "MetadataPreserveConfig",
    "MetadataPreserveParams",
    "ProcessConfig",
    "SchemaParseConfig",
    "SpaceHandlingOption",
    "TransformConfig",
    "ValidationConfig",
    "ValidationRuleSet",
    "WriteConfig",
]
