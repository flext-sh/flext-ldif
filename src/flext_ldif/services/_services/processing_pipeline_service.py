from __future__ import annotations

from typing import Final

from flext_ldif import FlextLdifProcessingPipeline, c, m, u

logger: Final = u.fetch_logger(__name__)


class FlextLdifProcessingPipelineService:
    """Factory service for LDIF processing pipelines."""

    @staticmethod
    def get_processing_pipeline(
        source_server_type: c.Ldif.ServerTypes,
        target_server_type: c.Ldif.ServerTypes,
    ) -> FlextLdifProcessingPipeline:
        """Create a processing pipeline configured for source/target servers."""
        logger.debug(
            "Creating processing pipeline",
            source=source_server_type,
            target=target_server_type,
        )
        settings = m.Ldif.TransformConfig.servers(
            source_server=source_server_type,
            target_server=target_server_type,
        )
        return FlextLdifProcessingPipeline(settings)


__all__: list[str] = ["FlextLdifProcessingPipelineService"]
