"""Service-layer pipeline orchestration."""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)

from flext_ldif import (
    FlextLdifTransformer,
    c,
    m,
    r,
    u,
)


class FlextLdifProcessingPipeline:
    """Full processing pipeline with configuration."""

    __slots__ = ("_config", "_pipeline")
    _DEFAULT_CASE_FOLD: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.NONE
    _DEFAULT_SPACE_HANDLING: c.Ldif.SpaceHandlingOption = (
        c.Ldif.SpaceHandlingOption.PRESERVE
    )

    def __init__(self, settings: m.Ldif.TransformConfig | None = None) -> None:
        """Initialize processing pipeline."""
        self._config = settings or m.Ldif.TransformConfig()
        self._pipeline = self._build_pipeline()

    @property
    def settings(self) -> m.Ldif.TransformConfig:
        """Get the processing configuration."""
        return self._config

    def execute(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Execute the processing pipeline."""
        return r[MutableSequence[m.Ldif.Entry]].from_result(
            self._pipeline.execute(entries),
        )

    def _build_pipeline(self) -> u.Ldif.Pipeline:
        """Build the internal pipeline based on configuration."""
        pipeline = u.Ldif.Pipeline()
        if self._config.normalize_dns and self._config.process_config is not None:
            dn_config = (
                self._config.process_config.dn_config or m.Ldif.DnNormalizationConfig()
            )
            case_enum = (
                c.Ldif.CaseFoldOption(dn_config.case_fold)
                if dn_config.case_fold is not None
                else self._DEFAULT_CASE_FOLD
            )
            spaces_enum = (
                c.Ldif.SpaceHandlingOption(dn_config.space_handling)
                if dn_config.space_handling is not None
                else self._DEFAULT_SPACE_HANDLING
            )
            pipeline.add(
                u.Ldif.Normalize.dn(
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
                u.Ldif.Normalize.attrs(
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
            source_server = c.Ldif.ServerTypes(
                u.Ldif.normalize_server_type(self._config.process_config.source_server),
            )
            target_server = c.Ldif.ServerTypes(
                u.Ldif.normalize_server_type(self._config.process_config.target_server),
            )
            pipeline.add(
                FlextLdifTransformer(
                    source_server=source_server,
                    target_server=target_server,
                ),
                name="server_transform",
            )
        return pipeline
