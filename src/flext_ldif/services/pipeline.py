"""Service-layer pipeline orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from flext_core import r

from flext_ldif._utilities.configs import TransformConfig
from flext_ldif._utilities.pipeline import Pipeline
from flext_ldif._utilities.transformers import Normalize
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.transformers import ServerTransformer


class ProcessingPipeline:
    """Full processing pipeline with configuration."""

    __slots__ = ("_config", "_pipeline")

    def __init__(self, config: TransformConfig | None = None) -> None:
        """Initialize processing pipeline."""
        self._config = config or TransformConfig()
        self._pipeline = self._build_pipeline()

    def _build_pipeline(self) -> Pipeline:
        """Build the internal pipeline based on configuration."""
        pipeline = Pipeline()

        # Add DN normalization if enabled
        if self._config.normalize_dns and self._config.process_config is not None:
            # Convert Literal to StrEnum for type compatibility
            dn_config = (
                self._config.process_config.dn_config or m.Ldif.DnNormalizationConfig()
            )
            case_fold_value = dn_config.case_fold or "none"
            space_handling_value = dn_config.space_handling or "preserve"

            case_enum = c.Ldif.CaseFoldOption(case_fold_value)
            spaces_enum = m.Ldif.SpaceHandlingOption(space_handling_value)

            pipeline.add(
                Normalize.dn(
                    case=case_enum,
                    spaces=spaces_enum,
                    validate=dn_config.validate_before,
                ),
                name="normalize_dn",
            )

        # Add attribute normalization if enabled
        if self._config.normalize_attrs and self._config.process_config is not None:
            attr_config = (
                self._config.process_config.attr_config
                or m.Ldif.AttrNormalizationConfig()
            )
            pipeline.add(
                Normalize.attrs(
                    case_fold_names=attr_config.case_fold_names,
                    trim_values=attr_config.trim_values,
                    remove_empty=attr_config.remove_empty,
                ),
                name="normalize_attrs",
            )

        # Add server-specific transformations if configured
        if (
            self._config.process_config is not None
            and self._config.process_config.source_server
            and self._config.process_config.target_server
        ):
            pipeline.add(
                ServerTransformer(
                    source_server=self._config.process_config.source_server,
                    target_server=self._config.process_config.target_server,
                ),
                name="server_transform",
            )

        return pipeline

    def execute(
        self,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Execute the processing pipeline."""
        return self._pipeline.execute(entries)

    @property
    def config(self) -> TransformConfig:
        """Get the processing configuration."""
        return self._config
