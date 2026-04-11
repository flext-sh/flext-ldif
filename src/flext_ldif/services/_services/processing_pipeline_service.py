from __future__ import annotations

from typing import Final

from flext_ldif import FlextLdifProcessingPipeline, c, m, u

logger: Final = u.fetch_logger(__name__)


class FlextLdifProcessingPipelineService:
    __slots__ = ("_processing_pipeline",)

    def __init__(self) -> None:
        self._processing_pipeline: FlextLdifProcessingPipeline | None = None

    def get_processing_pipeline(
        self,
        source_server_type: c.Ldif.ServerTypes,
        target_server_type: c.Ldif.ServerTypes,
    ) -> FlextLdifProcessingPipeline:
        pipeline = self._processing_pipeline
        if pipeline is None:
            logger.debug(
                "Creating processing pipeline",
                source=source_server_type,
                target=target_server_type,
            )
            process_config = m.Ldif.ProcessConfig(
                batch_size=100,
                timeout_seconds=300,
                max_retries=3,
                source_server=source_server_type,
                target_server=target_server_type,
                dn_config=None,
                attr_config=None,
            )
            config = m.Ldif.TransformConfig(
                fail_fast=False,
                preserve_order=True,
                track_changes=False,
                normalize_dns=False,
                normalize_attrs=False,
                process_config=process_config,
            )
            pipeline = FlextLdifProcessingPipeline(config)
            self._processing_pipeline = pipeline
        return pipeline


__all__ = ["FlextLdifProcessingPipelineService"]
