"""Service-layer pipeline orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import FlextLdifTransformer, Normalize, Pipeline, c, m, r


class FlextLdifProcessingPipeline:
    """Full processing pipeline with configuration."""

    __slots__ = ("_config", "_pipeline")

    def __init__(self, config: m.Ldif.TransformConfig | None = None) -> None:
        """Initialize processing pipeline."""
        self._config = config or m.Ldif.TransformConfig()
        self._pipeline = self._build_pipeline()

    @property
    def config(self) -> m.Ldif.TransformConfig:
        """Get the processing configuration."""
        return self._config

    def execute(self, entries: Sequence[m.Ldif.Entry]) -> r[Sequence[m.Ldif.Entry]]:
        """Execute the processing pipeline."""
        return self._pipeline.execute(entries)

    def _build_pipeline(self) -> Pipeline:
        """Build the internal pipeline based on configuration."""
        pipeline = Pipeline()
        if self._config.normalize_dns and self._config.process_config is not None:
            dn_config = (
                self._config.process_config.dn_config or m.Ldif.DnNormalizationConfig()
            )
            case_fold_value = dn_config.case_fold or "none"
            space_handling_value = dn_config.space_handling or "preserve"
            case_enum = c.Ldif.CaseFoldOption(case_fold_value)
            spaces_enum = c.Ldif.SpaceHandlingOption(space_handling_value)
            pipeline.add(
                Normalize.dn(
                    case=case_enum,
                    spaces=spaces_enum,
                    validate=dn_config.validate_before,
                ),
                name="normalize_dn",
            )
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
        if (
            self._config.process_config is not None
            and self._config.process_config.source_server
            and self._config.process_config.target_server
        ):
            source_server = c.Ldif.ServerTypes[
                self._config.process_config.source_server.upper()
            ]
            target_server = c.Ldif.ServerTypes[
                self._config.process_config.target_server.upper()
            ]
            pipeline.add(
                FlextLdifTransformer(
                    source_server=source_server,
                    target_server=target_server,
                ),
                name="server_transform",
            )
        return pipeline
