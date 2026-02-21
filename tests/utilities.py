"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

from pathlib import Path

from flext_ldif.utilities import FlextLdifUtilities
from flext_tests.utilities import FlextTestsUtilities

from tests.constants import RfcTestHelpers as _RfcTestHelpers, TestDeduplicationHelpers


class TestsFlextLdifUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    OID = FlextLdifUtilities.Ldif.OID
    TestDeduplicationHelpers = TestDeduplicationHelpers

    class RfcTestHelpers(_RfcTestHelpers):
        """Compatibility extension for RFC helper API."""

        @staticmethod
        def test_parse_ldif_file(
            parser_service: object,
            file_path: Path,
            expected_count: int,
            server_type: str = "rfc",
        ) -> list[object]:
            file_content = file_path.read_text(encoding="utf-8")
            return _RfcTestHelpers.test_parse_ldif_content(
                parser_service=parser_service,
                content=file_content,
                expected_count=expected_count,
                server_type=server_type,
            )

    class TestCategorization:
        """Test categorization utilities."""


u = TestsFlextLdifUtilities

__all__ = [
    "TestsFlextLdifUtilities",
    "u",
]
