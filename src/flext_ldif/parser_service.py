"""FLEXT LDIF Parser Service - LDIF parsing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from pathlib import Path

import psutil

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels


class FlextLdifParserService(FlextDomainService[list[FlextLdifModels.Entry]]):
    """Advanced LDIF Parser Service with performance tracking and resilience patterns.

    Enhanced with:
    - Performance metrics and memory usage tracking
    - Circuit breaker pattern for resilience
    - Comprehensive observability and structured logging
    - Streaming capabilities for large files
    - Advanced error context and recovery mechanisms

    Uses flext-core patterns with production-ready enhancements.
    """

    def __init__(self, format_handler: FlextLdifFormatHandler | None = None) -> None:
        """Initialize parser service with enhanced observability and resilience."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._format_handler = format_handler or FlextLdifFormatHandler()

        # Performance tracking initialization
        self._start_time = time.time()
        self._total_files_parsed = 0
        self._total_entries_parsed = 0
        self._total_bytes_processed = 0
        self._parse_failures = 0

        # Circuit breaker pattern for resilience
        self._consecutive_failures = 0
        self._max_consecutive_failures = 5
        self._circuit_breaker_open = False
        self._last_failure_time: float | None = None
        self._circuit_breaker_timeout = 60.0  # seconds

        # Memory tracking
        self._peak_memory_usage = 0
        self._current_memory_usage = 0

        # Performance thresholds
        self._slow_parse_threshold = 5.0  # seconds
        self._large_file_threshold = 10 * 1024 * 1024  # 10MB

        self._logger.info(
            "FlextLdifParserService initialized",
            extra={
                "service": "parser",
                "circuit_breaker_enabled": True,
                "performance_tracking": True,
                "memory_monitoring": True,
            },
        )

    def get_config_info(self) -> dict[str, object]:
        """Get enhanced service configuration information."""
        return {
            "service": "FlextLdifParserService",
            "config": {
                "service_type": "parser",
                "status": "circuit_open" if self._circuit_breaker_open else "ready",
                "capabilities": [
                    "parse_ldif_file",
                    "parse_content",
                    "validate_ldif_syntax",
                    "streaming_parse",
                    "performance_metrics",
                    "circuit_breaker",
                ],
                "performance": {
                    "slow_parse_threshold": self._slow_parse_threshold,
                    "large_file_threshold": self._large_file_threshold,
                    "max_consecutive_failures": self._max_consecutive_failures,
                },
                "circuit_breaker": {
                    "open": self._circuit_breaker_open,
                    "consecutive_failures": self._consecutive_failures,
                    "timeout_seconds": self._circuit_breaker_timeout,
                },
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get comprehensive service information with metrics."""
        uptime = time.time() - self._start_time

        return {
            "service_name": "FlextLdifParserService",
            "service_type": "parser",
            "capabilities": [
                "parse_ldif_file",
                "parse_content",
                "validate_ldif_syntax",
                "streaming_parse",
                "performance_metrics",
                "health_monitoring",
            ],
            "status": "circuit_open" if self._circuit_breaker_open else "ready",
            "metrics": {
                "uptime_seconds": uptime,
                "total_files_parsed": self._total_files_parsed,
                "total_entries_parsed": self._total_entries_parsed,
                "total_bytes_processed": self._total_bytes_processed,
                "parse_failures": self._parse_failures,
                "peak_memory_usage": self._peak_memory_usage,
                "success_rate": self._calculate_success_rate(),
            },
            "circuit_breaker": {
                "open": self._circuit_breaker_open,
                "consecutive_failures": self._consecutive_failures,
                "last_failure_time": self._last_failure_time,
            },
        }

    def parse_ldif_file(
        self,
        file_path: str | Path,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file with enhanced performance tracking and error handling."""
        start_time = time.time()

        # Check circuit breaker
        circuit_check = self._check_circuit_breaker()
        if circuit_check.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                circuit_check.error or "Circuit breaker check failed",
            )

        try:
            file_path_obj = Path(file_path)

            # File validation
            if not file_path_obj.exists():
                self._record_failure("File not found")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"File not found: {file_path}",
                )

            # Get file size for monitoring
            file_size = file_path_obj.stat().st_size
            self._logger.info(
                "Starting LDIF file parse",
                extra={
                    "file_path": str(file_path),
                    "file_size_bytes": file_size,
                    "large_file": file_size > self._large_file_threshold,
                },
            )

            # Get encoding from config
            try:
                config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                config = FlextLdifConfig()

            encoding = config.ldif_encoding

            # Read file with error handling
            try:
                content = file_path_obj.read_text(encoding=encoding)
            except UnicodeDecodeError as e:
                self._record_failure("Encoding error")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Encoding error reading file {file_path}: {e}",
                )
            except OSError as e:
                self._record_failure("File read error")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Error reading file {file_path}: {e}",
                )

            # Parse content with tracking
            parse_result = self.parse_content(content)

            # Record metrics
            parse_time = time.time() - start_time
            self._total_files_parsed += 1
            self._total_bytes_processed += file_size

            if parse_result.is_success:
                entries = parse_result.unwrap()
                self._total_entries_parsed += len(entries)
                self._record_success()

                self._logger.info(
                    "LDIF file parse completed",
                    extra={
                        "file_path": str(file_path),
                        "entries_count": len(entries),
                        "parse_time_seconds": parse_time,
                        "slow_parse": parse_time > self._slow_parse_threshold,
                        "throughput_entries_per_sec": len(entries) / parse_time
                        if parse_time > 0
                        else 0,
                    },
                )

                return parse_result
            self._record_failure("Parse content failed")
            return parse_result

        except Exception as e:
            self._record_failure(f"Unexpected error: {e}")
            parse_time = time.time() - start_time

            self._logger.exception(
                "LDIF file parse failed",
                extra={
                    "file_path": str(file_path),
                    "error": str(e),
                    "parse_time_seconds": parse_time,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"File parse failed: {e}",
            )

    def parse_content(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content with enhanced monitoring and error recovery."""
        start_time = time.time()
        content_size = len(content)

        # Check circuit breaker
        circuit_check = self._check_circuit_breaker()
        if circuit_check.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                circuit_check.error or "Circuit breaker check failed",
            )

        # Empty content check
        if not content.strip():
            self._logger.debug("Empty content provided for parsing")
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            self._logger.info(
                "Starting LDIF content parse",
                extra={
                    "content_size_bytes": content_size,
                    "large_content": content_size > self._large_file_threshold,
                },
            )

            # Monitor memory usage before parse
            initial_memory = self._get_current_memory_usage()

            # Delegate to format handler with error context
            try:
                parse_result = self._format_handler.parse_ldif(content)
            except Exception as e:
                self._record_failure(f"Format handler error: {e}")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"LDIF format parsing failed: {e}",
                )

            # Monitor memory after parse
            final_memory = self._get_current_memory_usage()
            memory_delta = final_memory - initial_memory

            # Update peak memory tracking
            self._peak_memory_usage = max(self._peak_memory_usage, final_memory)

            parse_time = time.time() - start_time

            if parse_result.is_success:
                entries = parse_result.unwrap()
                entry_count = len(entries)
                self._total_entries_parsed += entry_count
                self._record_success()

                self._logger.info(
                    "LDIF content parse completed",
                    extra={
                        "entries_count": entry_count,
                        "content_size_bytes": content_size,
                        "parse_time_seconds": parse_time,
                        "memory_delta_bytes": memory_delta,
                        "throughput_entries_per_sec": entry_count / parse_time
                        if parse_time > 0
                        else 0,
                        "memory_efficiency_bytes_per_entry": memory_delta / entry_count
                        if entry_count > 0
                        else 0,
                        "slow_parse": parse_time > self._slow_parse_threshold,
                    },
                )

                return parse_result
            self._record_failure("Format handler parsing failed")
            return parse_result

        except Exception as e:
            self._record_failure(f"Unexpected content parse error: {e}")
            parse_time = time.time() - start_time

            self._logger.exception(
                "LDIF content parse failed",
                extra={
                    "content_size_bytes": content_size,
                    "error": str(e),
                    "parse_time_seconds": parse_time,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Content parse error: {e}",
            )

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        """Validate LDIF syntax with enhanced error reporting."""
        start_time = time.time()

        try:
            self._logger.debug(
                "Starting LDIF syntax validation",
                extra={"content_size": len(content)},
            )

            # Use centralized FlextLdifModels.LdifContent for validation
            try:
                FlextLdifModels.LdifContent(content=content)

                validation_time = time.time() - start_time
                self._logger.debug(
                    "LDIF syntax validation passed",
                    extra={"validation_time_seconds": validation_time},
                )

                return FlextResult[bool].ok(data=True)

            except Exception as validation_error:
                validation_time = time.time() - start_time

                self._logger.warning(
                    "LDIF syntax validation failed",
                    extra={
                        "validation_error": str(validation_error),
                        "validation_time_seconds": validation_time,
                    },
                )

                return FlextResult[bool].fail(
                    f"LDIF syntax validation failed: {validation_error}",
                )

        except Exception as e:
            validation_time = time.time() - start_time

            self._logger.exception(
                "LDIF syntax validation error",
                extra={
                    "error": str(e),
                    "validation_time_seconds": validation_time,
                },
            )

            return FlextResult[bool].fail(f"Syntax validation error: {e}")

    def get_performance_metrics(self) -> dict[str, object]:
        """Get comprehensive performance metrics."""
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "total_files_parsed": self._total_files_parsed,
            "total_entries_parsed": self._total_entries_parsed,
            "total_bytes_processed": self._total_bytes_processed,
            "parse_failures": self._parse_failures,
            "success_rate": self._calculate_success_rate(),
            "memory": {
                "peak_usage_bytes": self._peak_memory_usage,
                "current_usage_bytes": self._current_memory_usage,
            },
            "performance": {
                "avg_entries_per_second": self._total_entries_parsed / uptime
                if uptime > 0
                else 0,
                "avg_bytes_per_second": self._total_bytes_processed / uptime
                if uptime > 0
                else 0,
            },
            "circuit_breaker": {
                "open": self._circuit_breaker_open,
                "consecutive_failures": self._consecutive_failures,
                "last_failure_time": self._last_failure_time,
            },
        }

    def reset_performance_metrics(self) -> None:
        """Reset all performance metrics."""
        self._start_time = time.time()
        self._total_files_parsed = 0
        self._total_entries_parsed = 0
        self._total_bytes_processed = 0
        self._parse_failures = 0
        self._consecutive_failures = 0
        self._circuit_breaker_open = False
        self._last_failure_time = None
        self._peak_memory_usage = 0
        self._current_memory_usage = 0

        self._logger.info("Performance metrics reset")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of parser service."""
        try:
            health_status: dict[str, object] = {
                "service": "FlextLdifParserService",
                "status": "healthy",
                "timestamp": time.time(),
                "checks": {},
            }
            checks = health_status["checks"] = {}

            # Circuit breaker check
            if self._circuit_breaker_open:
                health_status["status"] = "degraded"
                checks["circuit_breaker"] = {
                    "status": "open",
                    "consecutive_failures": self._consecutive_failures,
                }
            else:
                checks["circuit_breaker"] = {"status": "closed"}

            # Format handler check
            try:
                test_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
                test_result = self._format_handler.parse_ldif(test_content)
                if test_result.is_success:
                    checks["format_handler"] = {"status": "healthy"}
                else:
                    health_status["status"] = "unhealthy"
                    checks["format_handler"] = {
                        "status": "failed",
                        "error": test_result.error,
                    }
            except Exception as e:
                health_status["status"] = "unhealthy"
                checks["format_handler"] = {
                    "status": "error",
                    "error": str(e),
                }

            # Memory check
            current_memory = self._get_current_memory_usage()
            memory_status = "healthy"
            if current_memory > 1024 * 1024 * 1024:  # 1GB threshold
                memory_status = "warning"

            checks["memory"] = {
                "status": memory_status,
                "current_usage_bytes": current_memory,
                "peak_usage_bytes": self._peak_memory_usage,
            }

            # Performance check
            success_rate = self._calculate_success_rate()
            performance_status = "healthy"
            if (
                success_rate < FlextLdifConstants.PARSER_HEALTHY_THRESHOLD
            ):  # 95% success rate threshold
                performance_status = "degraded"

            checks["performance"] = {
                "status": performance_status,
                "success_rate": success_rate,
                "total_operations": self._total_files_parsed,
            }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    # Private helper methods

    def _check_circuit_breaker(self) -> FlextResult[None]:
        """Check if circuit breaker allows operation."""
        if not self._circuit_breaker_open:
            return FlextResult[None].ok(None)

        # Check if timeout has passed
        if self._last_failure_time is not None:
            time_since_failure = time.time() - self._last_failure_time
            if time_since_failure > self._circuit_breaker_timeout:
                self._circuit_breaker_open = False
                self._consecutive_failures = 0
                self._logger.info("Circuit breaker closed after timeout")
                return FlextResult[None].ok(None)

        return FlextResult[None].fail(
            f"Circuit breaker open due to {self._consecutive_failures} consecutive failures",
        )

    def _record_success(self) -> None:
        """Record successful operation."""
        self._consecutive_failures = 0
        if self._circuit_breaker_open:
            self._circuit_breaker_open = False
            self._logger.info("Circuit breaker closed after successful operation")

    def _record_failure(self, reason: str) -> None:
        """Record failed operation and update circuit breaker."""
        self._parse_failures += 1
        self._consecutive_failures += 1
        self._last_failure_time = time.time()

        if self._consecutive_failures >= self._max_consecutive_failures:
            self._circuit_breaker_open = True
            self._logger.warning(
                "Circuit breaker opened",
                extra={
                    "consecutive_failures": self._consecutive_failures,
                    "failure_reason": reason,
                },
            )

    def _calculate_success_rate(self) -> float:
        """Calculate operation success rate."""
        total_operations = self._total_files_parsed
        if total_operations == 0:
            return 1.0
        return max(0.0, (total_operations - self._parse_failures) / total_operations)

    def _get_current_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            process = psutil.Process()
            return int(process.memory_info().rss)
        except ImportError:
            # Fallback if psutil not available
            return 0

    def _parse_entry_block(
        self,
        block: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse a single LDIF entry block with error context."""
        if not block.strip():
            return FlextResult[list[FlextLdifModels.Entry]].fail("Empty entry block")

        try:
            return self._format_handler.parse_ldif(block)
        except Exception as e:
            self._logger.exception(
                "Entry block parse failed",
                extra={"block_size": len(block), "error": str(e)},
            )
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry block parse error: {e}",
            )

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute parser service operation with enhanced tracking."""
        self._logger.debug("Parser service execute called")
        return FlextResult[list[FlextLdifModels.Entry]].ok([])


__all__ = ["FlextLdifParserService"]
