"""Service-layer pipeline orchestration."""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)
from typing import Annotated, Self, override

from flext_ldif import (
    FlextLdifTransformer,
    c,
    m,
    r,
    s,
    t,
    u,
)


class FlextLdifProcessingPipeline(s):
    """Full processing pipeline with configuration."""

    _DEFAULT_CASE_FOLD: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.NONE
    _DEFAULT_SPACE_HANDLING: c.Ldif.SpaceHandlingOption = (
        c.Ldif.SpaceHandlingOption.PRESERVE
    )
    transform_config: Annotated[
        m.Ldif.TransformConfig | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional transformation configuration for the processing pipeline.",
        ),
    ]
    _config: m.Ldif.TransformConfig = u.PrivateAttr(
        default_factory=m.Ldif.TransformConfig,
    )
    _pipeline: u.Ldif.Pipeline = u.PrivateAttr()

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Initialize the processing pipeline after model validation."""
        super().model_post_init(__context)
        self._config = self.transform_config or m.Ldif.TransformConfig()
        self._pipeline = self._build_pipeline()

    @classmethod
    def for_servers(
        cls,
        *,
        source_server: str | c.Ldif.ServerTypes,
        target_server: str | c.Ldif.ServerTypes,
    ) -> Self:
        """Create a configured pipeline for source and target LDIF servers."""
        source_server_type = (
            source_server
            if isinstance(source_server, c.Ldif.ServerTypes)
            else c.Ldif.ServerTypes(u.Ldif.normalize_server_type(source_server))
        )
        target_server_type = (
            target_server
            if isinstance(target_server, c.Ldif.ServerTypes)
            else c.Ldif.ServerTypes(u.Ldif.normalize_server_type(target_server))
        )
        cls._get_or_create_logger().debug(
            "Creating processing pipeline",
            source=source_server_type,
            target=target_server_type,
        )
        transform_config = m.Ldif.TransformConfig.servers(
            source_server=source_server_type,
            target_server=target_server_type,
        )
        return cls(transform_config=transform_config)

    @override
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
