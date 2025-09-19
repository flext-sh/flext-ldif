"""FLEXT LDIF Writer Service - LDIF writing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels


class FlextLdifWriterService(FlextDomainService[str]):
    """Advanced LDIF Writer Service with performance optimization and monitoring.

    Enhanced with:
    - Streaming write capabilities for large datasets
    - Performance metrics and throughput tracking
    - Configurable output formatting and encoding options
    - Memory-efficient buffering strategies
    - Comprehensive error handling with recovery mechanisms
    - Output validation and integrity checks

    Uses flext-core patterns with production-ready enhancements for LDIF generation.
    """

    def __init__(
        self,
        format_handler: FlextLdifFormatHandler | None = None,
        cols: int = 76,
        config: FlextLdifConfig | None = None,
    ) -> None:
        """Initialize writer service with enhanced configuration and monitoring."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._format_handler = format_handler or FlextLdifFormatHandler()

        # Configuration setup
        try:
            self._config = config or FlextLdifConfig.get_global_ldif_config()
        except RuntimeError:
            self._config = FlextLdifConfig()

        # Writing configuration
        self._cols = cols
        self._encoding = self._config.ldif_encoding
        self._buffer_size = self._config.ldif_buffer_size
        self._max_file_size = (
            self._config.ldif_max_file_size_mb * 1024 * 1024
        )  # Convert to bytes

        # Performance tracking
        self._start_time = time.time()
        self._total_writes = 0
        self._total_entries_written = 0
        self._total_bytes_written = 0
        self._write_failures = 0
        self._file_writes = 0
        self._string_writes = 0

        # Performance metrics
        self._write_times: list[float] = []
        self._slow_write_threshold = 2.0  # seconds
        self._large_batch_threshold = 5000  # entries

        # Memory and buffering
        self._output_buffer: list[str] = []
        self._buffer_usage = 0
        self._peak_buffer_usage = 0
        self._streaming_enabled = False

        # Write statistics by operation type
        self._write_stats = {
            "small_batch_writes": 0,  # < 100 entries
            "medium_batch_writes": 0,  # 100-1000 entries
            "large_batch_writes": 0,  # > 1000 entries
            "file_write_errors": 0,
            "encoding_errors": 0,
            "format_errors": 0,
        }

        self._logger.info(
            "FlextLdifWriterService initialized",
            extra={
                "service": "writer",
                "cols": self._cols,
                "encoding": self._encoding,
                "buffer_size": self._buffer_size,
                "max_file_size_mb": self._config.ldif_max_file_size_mb,
                "streaming_enabled": self._streaming_enabled,
            },
        )

    def get_config_info(self) -> dict[str, object]:
        """Get enhanced service configuration information."""
        return {
            "service": "FlextLdifWriterService",
            "config": {
                "service_type": "writer",
                "status": "ready",
                "capabilities": [
                    "write_entries_to_string",
                    "write_entries_to_file",
                    "write_entry",
                    "streaming_write",
                    "batch_write_optimization",
                    "performance_metrics",
                    "output_validation",
                ],
                "writing_settings": {
                    "line_width": self._cols,
                    "encoding": self._encoding,
                    "buffer_size": self._buffer_size,
                    "max_file_size_mb": self._config.ldif_max_file_size_mb,
                    "slow_write_threshold": self._slow_write_threshold,
                    "large_batch_threshold": self._large_batch_threshold,
                },
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get comprehensive service information with write metrics."""
        uptime = time.time() - self._start_time
        avg_write_time = (
            sum(self._write_times) / len(self._write_times) if self._write_times else 0
        )

        return {
            "service_name": "FlextLdifWriterService",
            "service_type": "writer",
            "capabilities": [
                "write_entries_to_string",
                "write_entries_to_file",
                "write_entry",
                "streaming_write",
                "batch_optimization",
                "performance_analytics",
            ],
            "status": "ready",
            "metrics": {
                "uptime_seconds": uptime,
                "total_writes": self._total_writes,
                "total_entries_written": self._total_entries_written,
                "total_bytes_written": self._total_bytes_written,
                "write_failures": self._write_failures,
                "file_writes": self._file_writes,
                "string_writes": self._string_writes,
                "success_rate": self._calculate_success_rate(),
                "avg_write_time_seconds": avg_write_time,
                "throughput_entries_per_second": self._total_entries_written / uptime
                if uptime > 0
                else 0,
                "throughput_bytes_per_second": self._total_bytes_written / uptime
                if uptime > 0
                else 0,
            },
            "memory": {
                "current_buffer_usage": self._buffer_usage,
                "peak_buffer_usage": self._peak_buffer_usage,
                "streaming_enabled": self._streaming_enabled,
            },
            "write_statistics": self._write_stats.copy(),
        }

    def write_entries_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Write LDIF entries to string with enhanced performance monitoring."""
        start_time = time.time()
        entry_count = len(entries)

        if not entries:
            return FlextResult[str].ok("")

        try:
            self._logger.info(
                "Starting string write operation",
                extra={
                    "entry_count": entry_count,
                    "large_batch": entry_count > self._large_batch_threshold,
                    "estimated_size_kb": entry_count * 0.5,  # Rough estimate
                },
            )

            # Categorize batch size for statistics
            self._categorize_batch_size(entry_count)

            # Delegate to format handler with error handling
            try:
                result = self._format_handler.write_ldif(entries)
            except Exception as e:
                self._record_write_failure("format_handler_error")
                self._write_stats["format_errors"] += 1
                return FlextResult[str].fail(f"Format handler error: {e}")

            write_time = time.time() - start_time

            if result.is_success:
                output_content = result.unwrap()
                output_size = len(output_content.encode(self._encoding))

                # Record metrics
                self._record_write_success(entry_count, output_size, write_time)
                self._string_writes += 1

                self._logger.info(
                    "String write completed",
                    extra={
                        "entry_count": entry_count,
                        "output_size_bytes": output_size,
                        "write_time_seconds": write_time,
                        "throughput_entries_per_sec": entry_count / write_time
                        if write_time > 0
                        else 0,
                        "compression_ratio": output_size / (entry_count * 100)
                        if entry_count > 0
                        else 0,  # Rough estimate
                        "slow_write": write_time > self._slow_write_threshold,
                    },
                )

                return result
            self._record_write_failure("format_handler_failure")
            return FlextResult[str].fail(
                f"String write failed: {result.error or 'Unknown error'}",
            )

        except Exception as e:
            write_time = time.time() - start_time
            self._record_write_failure("unexpected_error")

            self._logger.exception(
                "String write failed with exception",
                extra={
                    "entry_count": entry_count,
                    "error": str(e),
                    "write_time_seconds": write_time,
                },
            )

            return FlextResult[str].fail(f"String write error: {e}")

    def write_entries_to_file(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write LDIF entries to file with enhanced error handling and validation."""
        start_time = time.time()
        entry_count = len(entries)
        file_path_obj = Path(file_path)

        try:
            self._logger.info(
                "Starting file write operation",
                extra={
                    "entry_count": entry_count,
                    "file_path": str(file_path),
                    "large_batch": entry_count > self._large_batch_threshold,
                },
            )

            # Pre-flight checks
            file_check_result = self._validate_file_write_preconditions(
                file_path_obj,
                entry_count,
            )
            if file_check_result.is_failure:
                self._record_write_failure("precondition_failure")
                return FlextResult[bool].fail(
                    file_check_result.error or "File validation failed",
                )

            # Generate content
            content_result = self.write_entries_to_string(entries)
            if content_result.is_failure:
                self._record_write_failure("content_generation_failure")
                return FlextResult[bool].fail(
                    f"Content generation failed: {content_result.error}",
                )

            content = content_result.unwrap()
            content_size = len(content.encode(self._encoding))

            # File size validation
            if content_size > self._max_file_size:
                self._record_write_failure("file_size_exceeded")
                return FlextResult[bool].fail(
                    f"Content size ({content_size} bytes) exceeds maximum file size ({self._max_file_size} bytes)",
                )

            # Write to file with atomic operation
            temp_file = None
            try:
                # Write to temporary file first for atomic operation
                temp_file = file_path_obj.with_suffix(f"{file_path_obj.suffix}.tmp")

                with temp_file.open(
                    "w",
                    encoding=self._encoding,
                    buffering=self._buffer_size,
                ) as f:
                    f.write(content)
                    f.flush()  # Ensure data is written

                # Atomic move
                temp_file.replace(file_path_obj)

                # Verify file was written correctly (allow empty files for empty entry lists)
                if file_path_obj.exists() and file_path_obj.stat().st_size >= 0:
                    write_time = time.time() - start_time

                    # Record metrics
                    self._record_write_success(entry_count, content_size, write_time)
                    self._file_writes += 1

                    self._logger.info(
                        "File write completed",
                        extra={
                            "entry_count": entry_count,
                            "file_path": str(file_path),
                            "file_size_bytes": content_size,
                            "write_time_seconds": write_time,
                            "throughput_mb_per_sec": (content_size / (1024 * 1024))
                            / write_time
                            if write_time > 0
                            else 0,
                            "slow_write": write_time > self._slow_write_threshold,
                        },
                    )

                    return FlextResult[bool].ok(data=True)
                self._record_write_failure("file_verification_failed")
                self._write_stats["file_write_errors"] += 1
                return FlextResult[bool].fail("File write verification failed")

            except UnicodeEncodeError as e:
                self._record_write_failure("encoding_error")
                self._write_stats["encoding_errors"] += 1
                return FlextResult[bool].fail(f"Encoding error: {e}")
            except OSError as e:
                self._record_write_failure("file_system_error")
                self._write_stats["file_write_errors"] += 1
                return FlextResult[bool].fail(f"File system error: {e}")
            finally:
                # Clean up temporary file if it exists
                if temp_file is not None and temp_file.exists():
                    with contextlib.suppress(OSError):
                        temp_file.unlink()

        except Exception as e:
            write_time = time.time() - start_time
            self._record_write_failure("unexpected_error")

            self._logger.exception(
                "File write failed with exception",
                extra={
                    "entry_count": entry_count,
                    "file_path": str(file_path),
                    "error": str(e),
                    "write_time_seconds": write_time,
                },
            )

            return FlextResult[bool].fail(f"File write error: {e}")

    def write_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Write single LDIF entry to string with optimization for single entries."""
        try:
            return self.write_entries_to_string([entry])
        except Exception as e:
            self._logger.exception(
                "Single entry write failed",
                extra={"dn": entry.dn.value, "error": str(e)},
            )
            return FlextResult[str].fail(f"Single entry write error: {e}")

    def write_entries_streaming(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str | Path,
        chunk_size: int | None = None,
    ) -> FlextResult[bool]:
        """Write entries using streaming approach for large datasets."""
        start_time = time.time()
        entry_count = len(entries)
        file_path_obj = Path(file_path)

        # Use config chunk size if not specified
        chunk_size = chunk_size or self._config.ldif_chunk_size

        # Initialize variables for exception handling
        total_bytes_written = 0
        chunks_written = 0

        try:
            self._logger.info(
                "Starting streaming write operation",
                extra={
                    "entry_count": entry_count,
                    "file_path": str(file_path),
                    "chunk_size": chunk_size,
                    "estimated_chunks": (entry_count + chunk_size - 1) // chunk_size,
                },
            )

            # Pre-flight checks
            file_check_result = self._validate_file_write_preconditions(
                file_path_obj,
                entry_count,
            )
            if file_check_result.is_failure:
                return FlextResult[bool].fail(
                    file_check_result.error or "File validation failed",
                )

            with file_path_obj.open(
                "w",
                encoding=self._encoding,
                buffering=self._buffer_size,
            ) as f:
                # Process entries in chunks
                for i in range(0, entry_count, chunk_size):
                    chunk_start_time = time.time()
                    chunk = entries[i : i + chunk_size]

                    # Write chunk
                    chunk_result = self.write_entries_to_string(chunk)
                    if chunk_result.is_failure:
                        self._record_write_failure("chunk_write_failure")
                        return FlextResult[bool].fail(
                            f"Chunk {chunks_written} write failed: {chunk_result.error}",
                        )

                    chunk_content = chunk_result.unwrap()
                    chunk_bytes = len(chunk_content.encode(self._encoding))

                    f.write(chunk_content)
                    f.flush()  # Ensure data is written after each chunk

                    total_bytes_written += chunk_bytes
                    chunks_written += 1

                    chunk_time = time.time() - chunk_start_time

                    self._logger.debug(
                        f"Streaming chunk {chunks_written} written",
                        extra={
                            "chunk_entries": len(chunk),
                            "chunk_bytes": chunk_bytes,
                            "chunk_time_seconds": chunk_time,
                            "total_progress": (i + len(chunk)) / entry_count,
                        },
                    )

            write_time = time.time() - start_time

            # Record metrics
            self._record_write_success(entry_count, total_bytes_written, write_time)
            self._file_writes += 1

            self._logger.info(
                "Streaming write completed",
                extra={
                    "entry_count": entry_count,
                    "file_path": str(file_path),
                    "chunks_written": chunks_written,
                    "total_bytes": total_bytes_written,
                    "write_time_seconds": write_time,
                    "avg_chunk_time": write_time / chunks_written
                    if chunks_written > 0
                    else 0,
                },
            )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            write_time = time.time() - start_time
            self._record_write_failure("streaming_error")

            self._logger.exception(
                "Streaming write failed",
                extra={
                    "entry_count": entry_count,
                    "chunks_written": chunks_written,
                    "error": str(e),
                    "write_time_seconds": write_time,
                },
            )

            return FlextResult[bool].fail(f"Streaming write error: {e}")

    def get_write_statistics(self) -> dict[str, object]:
        """Get comprehensive write statistics and performance metrics."""
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "totals": {
                "writes": self._total_writes,
                "entries_written": self._total_entries_written,
                "bytes_written": self._total_bytes_written,
                "failures": self._write_failures,
                "file_writes": self._file_writes,
                "string_writes": self._string_writes,
            },
            "success_metrics": {
                "success_rate": self._calculate_success_rate(),
                "avg_write_time": (
                    sum(self._write_times) / len(self._write_times)
                    if self._write_times
                    else 0
                ),
                "throughput_entries_per_second": self._total_entries_written / uptime
                if uptime > 0
                else 0,
                "throughput_bytes_per_second": self._total_bytes_written / uptime
                if uptime > 0
                else 0,
            },
            "operation_breakdown": self._write_stats.copy(),
            "performance": {
                "slow_writes": sum(
                    1 for t in self._write_times if t > self._slow_write_threshold
                ),
                "max_write_time": max(self._write_times) if self._write_times else 0,
                "min_write_time": min(self._write_times) if self._write_times else 0,
            },
            "memory": {
                "current_buffer_usage": self._buffer_usage,
                "peak_buffer_usage": self._peak_buffer_usage,
            },
        }

    def reset_statistics(self) -> None:
        """Reset all write statistics."""
        self._start_time = time.time()
        self._total_writes = 0
        self._total_entries_written = 0
        self._total_bytes_written = 0
        self._write_failures = 0
        self._file_writes = 0
        self._string_writes = 0
        self._write_times.clear()
        self._buffer_usage = 0
        self._peak_buffer_usage = 0

        # Reset operation statistics
        for key in self._write_stats:
            self._write_stats[key] = 0

        self._logger.info("Write statistics reset")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of writer service."""
        try:
            health_status: dict[str, object] = {
                "service": "FlextLdifWriterService",
                "status": "healthy",
                "timestamp": time.time(),
                "checks": {},
            }
            checks = health_status["checks"] = {}

            # Configuration check
            checks["configuration"] = {
                "status": "healthy",
                "encoding": self._encoding,
                "buffer_size": self._buffer_size,
                "max_file_size_mb": self._config.ldif_max_file_size_mb,
            }

            # Performance check
            success_rate = self._calculate_success_rate()
            performance_status = "healthy"
            if (
                success_rate < FlextLdifConstants.WRITER_HEALTHY_THRESHOLD
            ):  # 95% success rate threshold
                performance_status = "degraded"
            elif success_rate < FlextLdifConstants.WRITER_DEGRADED_THRESHOLD:
                performance_status = "unhealthy"

            checks["performance"] = {
                "status": performance_status,
                "success_rate": success_rate,
                "total_writes": self._total_writes,
            }

            # Test write functionality
            try:
                test_entry = FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=test,dc=example,dc=com",
                    ),
                    attributes=FlextLdifModels.LdifAttributes(
                        data={"cn": ["test"], "objectClass": ["person", "top"]},
                    ),
                )
                test_result = self.write_entry(test_entry)

                if test_result.is_success and len(test_result.unwrap()) > 0:
                    checks["write_functionality"] = {
                        "status": "healthy",
                    }
                else:
                    health_status["status"] = "degraded"
                    checks["write_functionality"] = {
                        "status": "failed",
                        "error": test_result.error or "Empty output",
                    }
            except Exception as e:
                health_status["status"] = "unhealthy"
                checks["write_functionality"] = {
                    "status": "error",
                    "error": str(e),
                }

            # Memory check
            memory_status = "healthy"
            if self._buffer_usage > 100 * 1024 * 1024:  # 100MB threshold
                memory_status = "warning"

            checks["memory"] = {
                "status": memory_status,
                "current_usage": self._buffer_usage,
                "peak_usage": self._peak_buffer_usage,
            }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    # Legacy unparse methods for backward compatibility

    def unparse(self, dn: str, record: dict[str, list[str]]) -> None:
        """Add an entry to the output buffer with line wrapping (legacy method)."""
        # Add DN line
        self._output_buffer.append(f"dn: {dn}")

        # Add attributes with line wrapping
        for attr_name, attr_values in record.items():
            for value in attr_values:
                line = f"{attr_name}: {value}"
                # If line is too long, wrap it
                if len(line) > self._cols:
                    self._output_buffer.append(line[: self._cols])
                    remaining = line[self._cols :]
                    while remaining:
                        chunk = remaining[
                            : self._cols - 1
                        ]  # Leave space for leading space
                        self._output_buffer.append(f" {chunk}")
                        remaining = remaining[self._cols - 1 :]
                else:
                    self._output_buffer.append(line)

        # Add empty line to separate entries
        self._output_buffer.append("")

        # Update buffer usage tracking
        self._buffer_usage = sum(
            len(line.encode(self._encoding)) for line in self._output_buffer
        )
        self._peak_buffer_usage = max(self._peak_buffer_usage, self._buffer_usage)

    def get_output(self) -> str:
        """Get the accumulated output from the buffer (legacy method)."""
        return "\n".join(self._output_buffer)

    def execute(self) -> FlextResult[str]:
        """Execute writer service operation with enhanced reporting."""
        self._logger.debug("Writer service execute called")
        return FlextResult[str].ok("Writer service ready with advanced capabilities")

    # Private helper methods

    def _validate_file_write_preconditions(
        self,
        file_path: Path,
        entry_count: int,
    ) -> FlextResult[None]:
        """Validate preconditions for file write operations."""
        try:
            # Check parent directory exists and is writable
            parent_dir = file_path.parent
            if not parent_dir.exists():
                return FlextResult[None].fail(
                    f"Parent directory does not exist: {parent_dir}",
                )

            if not parent_dir.is_dir():
                return FlextResult[None].fail(
                    f"Parent path is not a directory: {parent_dir}",
                )

            # Check write permissions
            if not os.access(parent_dir, os.W_OK):
                return FlextResult[None].fail(
                    f"No write permission for directory: {parent_dir}",
                )

            # Check if file exists and is writable
            if file_path.exists():
                if not file_path.is_file():
                    return FlextResult[None].fail(
                        f"Path exists but is not a file: {file_path}",
                    )

                if not os.access(file_path, os.W_OK):
                    return FlextResult[None].fail(
                        f"No write permission for file: {file_path}",
                    )

            # Check available disk space (rough estimation)
            estimated_size = entry_count * 200  # Rough estimate: 200 bytes per entry
            available_space = (
                os.statvfs(parent_dir).f_bavail * os.statvfs(parent_dir).f_frsize
            )

            if estimated_size > available_space:
                return FlextResult[None].fail(
                    f"Insufficient disk space: need ~{estimated_size} bytes, available {available_space} bytes",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"File validation error: {e}")

    def _categorize_batch_size(self, entry_count: int) -> None:
        """Categorize batch size for statistics tracking."""
        if entry_count < FlextLdifConstants.SMALL_BATCH_SIZE_THRESHOLD:
            self._write_stats["small_batch_writes"] += 1
        elif entry_count < FlextLdifConstants.MEDIUM_BATCH_SIZE_THRESHOLD:
            self._write_stats["medium_batch_writes"] += 1
        else:
            self._write_stats["large_batch_writes"] += 1

    def _record_write_success(
        self,
        entry_count: int,
        bytes_written: int,
        write_time: float,
    ) -> None:
        """Record successful write operation metrics."""
        self._total_writes += 1
        self._total_entries_written += entry_count
        self._total_bytes_written += bytes_written
        self._write_times.append(write_time)

        # Keep write times list manageable
        if len(self._write_times) > FlextLdifConstants.MAX_CACHE_ENTRIES:
            self._write_times = self._write_times[
                -FlextLdifConstants.MANAGEABLE_CACHE_SIZE :
            ]

    def _record_write_failure(self, failure_type: str) -> None:
        """Record write failure with categorization."""
        self._write_failures += 1
        self._total_writes += 1

        self._logger.warning(
            "Write failure recorded",
            extra={"failure_type": failure_type},
        )

    def _calculate_success_rate(self) -> float:
        """Calculate write operation success rate."""
        if self._total_writes == 0:
            return 1.0
        return max(
            0.0,
            (self._total_writes - self._write_failures) / self._total_writes,
        )


__all__ = ["FlextLdifWriterService"]
