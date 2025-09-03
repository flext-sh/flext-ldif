"""Enterprise E2E tests for complete LDIF processing workflows.

End-to-end tests that validate complete workflows from input to output,
covering real-world scenarios and enterprise use cases.
"""

from __future__ import annotations

import gc
import queue
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from flext_core import FlextResult

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFConfig,
    FlextLDIFCore,
    FlextLDIFFormatHandler,
)

# Constants
EXPECTED_DATA_COUNT = 3


class TestE2EEnterpriseWorkflows:
    """Enterprise E2E tests for complete LDIF workflows."""

    @pytest.fixture
    def enterprise_ldif_sample(self) -> str:
        """Enterprise LDIF sample with various entry types."""
        return """dn: dc=enterprise,dc=com
objectClass: top
objectClass: domain
dc: enterprise
description: Enterprise root domain

dn: ou=people,dc=enterprise,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people
description: People organizational unit

dn: ou=groups,dc=enterprise,dc=com
objectClass: top
objectClass: organizationalUnit
ou: groups
description: Groups organizational unit

dn: cn=John Smith,ou=people,dc=enterprise,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: John Smith
sn: Smith
givenName: John
displayName: John Smith
mail: john.smith@enterprise.com
uid: jsmith
employeeNumber: EMP001
telephoneNumber: +1-555-0101
title: Software Engineer
departmentNumber: IT-DEV
manager: cn=Alice Johnson,ou=people,dc=enterprise,dc=com

dn: cn=Alice Johnson,ou=people,dc=enterprise,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
givenName: Alice
displayName: Alice Johnson
mail: alice.johnson@enterprise.com
uid: ajohnson
employeeNumber: EMP002
telephoneNumber: +1-555-0102
title: Engineering Manager
departmentNumber: IT-DEV

dn: cn=Bob Wilson,ou=people,dc=enterprise,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Bob Wilson
sn: Wilson
givenName: Bob
displayName: Bob Wilson
mail: bob.wilson@enterprise.com
uid: bwilson
employeeNumber: EMP003
telephoneNumber: +1-555-0103
title: DevOps Engineer
departmentNumber: IT-OPS

dn: cn=developers,ou=groups,dc=enterprise,dc=com
objectClass: top
objectClass: groupOfNames
cn: developers
description: Software developers group
member: cn=John Smith,ou=people,dc=enterprise,dc=com
member: cn=Alice Johnson,ou=people,dc=enterprise,dc=com

dn: cn=managers,ou=groups,dc=enterprise,dc=com
objectClass: top
objectClass: groupOfNames
cn: managers
description: Management group
member: cn=Alice Johnson,ou=people,dc=enterprise,dc=com

dn: cn=it-staff,ou=groups,dc=enterprise,dc=com
objectClass: top
objectClass: groupOfNames
cn: it-staff
description: IT Staff group
member: cn=John Smith,ou=people,dc=enterprise,dc=com
member: cn=Alice Johnson,ou=people,dc=enterprise,dc=com
member: cn=Bob Wilson,ou=people,dc=enterprise,dc=com

"""

    def test_e2e_complete_ldif_processing_workflow(
        self,
        enterprise_ldif_sample: str,
    ) -> None:
        """Test complete LDIF processing workflow from input to output."""
        # Step 1: Parse LDIF content
        api = FlextLDIFAPI()
        parse_result = api.parse(enterprise_ldif_sample)

        assert parse_result.is_success
        if len(parse_result.value) != 9:  # 9 entries total
            msg: str = f"Expected 9 entries total, got {len(parse_result.value)}"
            raise AssertionError(msg)
        entries = parse_result.value

        # Step 2: Validate all entries
        validate_result = api.validate(entries)
        assert validate_result.is_success

        # Step 3: Filter person entries
        person_filter_result = api.filter_persons(entries)
        assert person_filter_result.is_success
        person_entries = person_filter_result.value
        if len(person_entries) != EXPECTED_DATA_COUNT:  # John, Alice, Bob
            msg: str = f"Expected 3 (John, Alice, Bob), got {len(person_entries)}"
            raise AssertionError(msg)

        # Step 4: Filter by specific objectClass
        inetorg_result = api.filter_by_objectclass(entries, "inetOrgPerson")
        if not inetorg_result.is_success:
            msg: str = f"Filter by objectClass failed: {inetorg_result.error}"
            raise AssertionError(msg)
        inetorg_entries = inetorg_result.value
        if len(inetorg_entries) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(inetorg_entries)}"
            raise AssertionError(msg)

        # Step 5: Sort hierarchically
        sort_result = api.sort_hierarchically(entries)
        assert sort_result.is_success
        sorted_entries = sort_result.value

        # Root domain should come first (fewer commas in DN)
        root_entry = sorted_entries[0]
        if str(root_entry.dn) != "dc=enterprise,dc=com":
            msg: str = f"Expected dc=enterprise,dc=com, got {root_entry.dn!s}"
            raise AssertionError(msg)

        # Step 6: Find specific entry by DN
        target_dn = "cn=John Smith,ou=people,dc=enterprise,dc=com"
        found_result = api.find_entry_by_dn(entries, target_dn)
        assert found_result.is_success
        found_entry = found_result.value
        assert found_entry is not None
        if found_entry.get_attribute("employeeNumber") != ["EMP001"]:
            msg: str = f"Expected ['EMP001'], got {found_entry.get_attribute('employeeNumber')}"
            raise AssertionError(msg)

        # Step 7: Write back to LDIF
        write_result = api.write(sorted_entries)
        assert write_result.is_success
        output_ldif = write_result.value

        # Step 8: Validate round-trip integrity
        reparse_result = api.parse(output_ldif)
        assert reparse_result.is_success
        if len(reparse_result.value) != len(sorted_entries):
            msg: str = (
                f"Expected {len(sorted_entries)}, got {len(reparse_result.value)}"
            )
            raise AssertionError(msg)

    def test_e2e_file_processing_workflow(self, enterprise_ldif_sample: str) -> None:
        """Test complete file processing workflow."""
        api = FlextLDIFAPI()

        # Create temporary input file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as input_file:
            input_file.write(enterprise_ldif_sample)
            input_path = Path(input_file.name)

        # Create temporary output file path
        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as output_file:
            output_path = Path(output_file.name)

        try:
            # Step 1: Parse from file
            parse_result = api.parse_file(input_path)
            assert parse_result.is_success
            entries = parse_result.value

            # Step 2: Process entries (filter and sort)
            person_result = api.filter_persons(entries)
            assert person_result.is_success
            person_entries = person_result.value

            sort_result = api.sort_hierarchically(person_entries)
            assert sort_result.is_success
            sorted_persons = sort_result.value

            # Step 3: Write to output file
            write_result = api.write_file(sorted_persons, output_path)
            assert write_result.is_success

            # Step 4: Verify output file
            assert output_path.exists()
            output_content = output_path.read_text(encoding="utf-8")
            assert len(output_content) > 0
            if "cn=John Smith" not in output_content:
                msg: str = f"Expected 'cn=John Smith' in {output_content}"
                raise AssertionError(msg)

            # Step 5: Re-read and validate
            reread_result = api.parse_file(output_path)
            assert reread_result.is_success
            if len(reread_result.value) != len(sorted_persons):
                msg: str = (
                    f"Expected {len(sorted_persons)}, got {len(reread_result.value)}"
                )
                raise AssertionError(msg)

        finally:
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    def test_e2e_core_tldif_workflow(self, enterprise_ldif_sample: str) -> None:
        """Test complete workflow using FlextLDIFAPI core directly."""
        # Use the main API instead of TLdif directly
        api = FlextLDIFAPI()

        # Step 1: Parse using main API
        parse_result = api.parse(enterprise_ldif_sample)
        assert parse_result.is_success
        entries = parse_result.value

        # Step 2: Validate using main API
        validate_result = api.validate(entries)
        assert validate_result.is_success

        # Step 3: Write using main API
        write_result = api.write(entries)
        assert write_result.is_success
        output_content = write_result.value

        # Step 4: Round-trip test
        reparse_result = api.parse(output_content)
        assert reparse_result.is_success
        if len(reparse_result.value) != len(entries):
            msg: str = f"Expected {len(entries)}, got {len(reparse_result.value)}"
            raise AssertionError(msg)

        # Step 5: File operations
        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            # Write to file
            file_write_result = api.write_file(entries, str(temp_path))
            assert file_write_result.is_success

            # Read from file
            file_read_result = api.parse_file(temp_path)
            assert file_read_result.is_success
            if len(file_read_result.value) != len(entries):
                msg: str = f"Expected {len(entries)}, got {len(file_read_result.value)}"
                raise AssertionError(msg)

        finally:
            temp_path.unlink(missing_ok=True)

    def test_e2e_convenience_functions_workflow(
        self,
        enterprise_ldif_sample: str,
    ) -> None:
        """Test complete workflow using convenience functions."""
        # Step 1: Parse using convenience function
        entries = FlextResult.unwrap_or_raise(
            FlextLDIFFormatHandler.parse_ldif(enterprise_ldif_sample)
        )
        if len(entries) != 9:
            msg: str = f"Expected {9}, got {len(entries)}"
            raise AssertionError(msg)

        # Step 2: Validate using convenience function (SOLID fix: validate parsed entries, not raw LDIF)
        is_valid = FlextResult.unwrap_or_raise(
            FlextLDIFCore().validate_entries(entries)
        )
        if not (is_valid):
            msg: str = f"Expected True, got {is_valid}"
            raise AssertionError(msg)

        # Step 3: Write using convenience function
        output_content = FlextResult.unwrap_or_raise(
            FlextLDIFFormatHandler.write_ldif(entries)
        )
        assert len(output_content) > 0

        # Step 4: Round-trip with convenience functions
        reparsed_entries = FlextResult.unwrap_or_raise(
            FlextLDIFFormatHandler.parse_ldif(output_content)
        )
        if len(reparsed_entries) != len(entries):
            msg: str = f"Expected {len(entries)}, got {len(reparsed_entries)}"
            raise AssertionError(msg)

        # Step 5: File output (SOLID fix: use API for file operations)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            # Use API for file writing, convenience function only returns string content
            api = FlextLDIFAPI()
            file_result = api.write_file(entries, temp_path)
            assert file_result.is_success
            assert temp_path.exists()

        finally:
            temp_path.unlink(missing_ok=True)

    def test_e2e_configuration_scenarios(self, enterprise_ldif_sample: str) -> None:
        """Test E2E workflows with different configurations."""
        # Scenario 1: Strict configuration
        strict_config = FlextLDIFConfig.model_validate(
            {
                "strict_validation": True,
                "max_entries": 20,
                "max_line_length": 120,
            },
        )

        strict_api = FlextLDIFAPI(strict_config)
        strict_result = strict_api.parse(enterprise_ldif_sample)
        assert strict_result.is_success  # Should pass with valid data

        # Scenario 2: Permissive configuration
        permissive_config = FlextLDIFConfig.model_validate(
            {
                "strict_validation": False,
                "max_entries": 1000,
                "max_line_length": 200,
            },
        )

        permissive_api = FlextLDIFAPI(permissive_config)
        permissive_result = permissive_api.parse(enterprise_ldif_sample)
        assert permissive_result.is_success

        # Scenario 3: Restrictive configuration
        restrictive_config = FlextLDIFConfig.model_validate(
            {
                "max_entries": 5,  # Less than our sample
            },
        )

        restrictive_api = FlextLDIFAPI(restrictive_config)
        restrictive_result = restrictive_api.parse(enterprise_ldif_sample)
        assert not restrictive_result.is_success  # Should fail due to limits

    def test_e2e_error_recovery_workflow(self) -> None:
        """Test E2E workflow with error conditions and recovery."""
        api = FlextLDIFAPI()

        # Step 1: Try to parse invalid content
        invalid_content = "This is not LDIF content at all"
        parse_result = api.parse(invalid_content)
        assert not parse_result.is_success
        assert parse_result.error is not None

        # Step 2: Try to parse partially valid content
        partial_content = """dn: cn=valid,dc=example,dc=com
objectClass: person
cn: valid

dn: invalid-dn-format
cn: invalid
objectClass: person
"""

        partial_result = api.parse(partial_content)
        # Should handle gracefully (may succeed with valid entry only)
        assert partial_result is not None

        # Step 3: Try file operations with nonexistent files
        nonexistent_file = Path("/nonexistent/file.ldif")
        file_result = api.parse_file(nonexistent_file)
        assert not file_result.is_success
        if (
            file_result.error is not None
            and "not found" not in file_result.error.lower()
        ):
            msg: str = f"Expected 'not found' in {file_result.error.lower() if file_result.error else 'None'}"
            raise AssertionError(msg)

    def test_e2e_performance_workflow(self) -> None:
        """Test E2E workflow performance with larger datasets."""
        # Generate larger LDIF content
        large_content = """dn: dc=performance,dc=com
objectClass: top
objectClass: domain
dc: performance

dn: ou=people,dc=performance,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

"""

        # Add many person entries
        for i in range(50):
            large_content += f"""dn: cn=user{i:03d},ou=people,dc=performance,dc=com
objectClass: top
objectClass: person
objectClass: inetOrgPerson
cn: user{i:03d}
sn: User{i:03d}
givenName: Test{i:03d}
mail: user{i:03d}@performance.com
uid: user{i:03d}
employeeNumber: EMP{i:03d}

"""

        api = FlextLDIFAPI()

        # Time the complete workflow
        start_time = time.time()

        # Parse
        parse_result = api.parse(large_content)
        assert parse_result.is_success
        parse_time = time.time()

        # Filter
        person_result = api.filter_persons(parse_result.value)
        assert person_result.is_success
        filter_time = time.time()

        # Sort
        sort_result = api.sort_hierarchically(person_result.value)
        assert sort_result.is_success
        sort_time = time.time()

        # Write
        write_result = api.write(sort_result.value)
        assert write_result.is_success
        write_time = time.time()

        # Calculate timings
        total_time = write_time - start_time
        parse_duration = parse_time - start_time
        filter_duration = filter_time - parse_time
        sort_duration = sort_time - filter_time
        write_duration = write_time - sort_time

        # Performance assertions
        assert total_time < 5.0  # Total should be under 5 seconds
        assert parse_duration < 2.0  # Parse should be under 2 seconds
        assert filter_duration < 1.0  # Filter should be under 1 second
        assert sort_duration < 1.0  # Sort should be under 1 second
        assert write_duration < 2.0  # Write should be under 2 seconds

        # Verify results
        if len(parse_result.value) != 52:  # 2 structure + 50 people
            msg: str = (
                f"Expected 52 (2 structure + 50 people), got {len(parse_result.value)}"
            )
            raise AssertionError(msg)
        assert len(person_result.value) == 50  # 50 people
        if len(sort_result.value) != 50:  # Same after sorting
            msg: str = f"Expected 50 (same after sorting), got {len(sort_result.value)}"
            raise AssertionError(msg)

    def test_e2e_memory_efficiency_workflow(self) -> None:
        """Test E2E workflow memory efficiency."""
        # Generate medium-sized LDIF content
        content = ""
        for i in range(20):
            content += f"""dn: cn=user{i},dc=memory,dc=com
objectClass: person
cn: user{i}
sn: User{i}
mail: user{i}@memory.com
description: User number {i} for memory testing

"""

        # Measure memory before
        gc.collect()
        memory_before = sys.getsizeof(content)

        api = FlextLDIFAPI()

        # Process workflow
        parse_result = api.parse(content)
        person_result = api.filter_persons(parse_result.value)
        sort_result = api.sort_hierarchically(person_result.value)
        write_result = api.write(sort_result.value)

        # Measure memory after
        gc.collect()
        total_memory = (
            sys.getsizeof(parse_result.value)
            + sys.getsizeof(person_result.value)
            + sys.getsizeof(sort_result.value)
            + sys.getsizeof(write_result.value)
        )

        # Memory usage should be reasonable (not more than 5x input)
        memory_ratio = total_memory / memory_before
        assert memory_ratio < 5.0

    def _execute_workflow(self, ldif_sample: str) -> str:
        """Execute a single LDIF workflow."""
        try:
            api = FlextLDIFAPI()

            parse_result = api.parse(ldif_sample)
            if not parse_result.is_success:
                return "failed"

            person_result = api.filter_persons(parse_result.value)
            if not person_result.is_success:
                return "failed"

            write_result = api.write(person_result.value)
            if not write_result.is_success:
                return "failed"
        except (RuntimeError, ValueError, TypeError):
            return "failed"
        else:
            return "success"

    def test_e2e_concurrent_workflows(self, enterprise_ldif_sample: str) -> None:
        """Test concurrent E2E workflows."""
        results: queue.Queue[str] = queue.Queue()

        def worker_workflow() -> None:
            result = self._execute_workflow(enterprise_ldif_sample)
            results.put(result)

        # Start multiple worker threads
        threads: list[threading.Thread] = []
        for _ in range(5):
            thread = threading.Thread(target=worker_workflow)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify all succeeded
        success_count = 0
        while not results.empty():
            if results.get() == "success":
                success_count += 1

        if success_count != 5:  # All workflows should succeed
            msg: str = f"Expected 5 (all workflows should succeed), got {success_count}"
            raise AssertionError(msg)

    def test_e2e_real_world_scenario(self) -> None:
        """Test real-world enterprise scenario workflow."""
        # Simulate typical enterprise LDAP export processing

        # Step 1: Create realistic enterprise data
        enterprise_data = self._create_realistic_enterprise_data()

        # Step 2: Process with enterprise requirements
        config = FlextLDIFConfig.model_validate(
            {
                "strict_validation": True,
                "max_entries": 500,
            },
        )

        api = FlextLDIFAPI(config)

        # Step 3: Parse and validate
        parse_result = api.parse(enterprise_data)
        assert parse_result.is_success

        # Step 4: Extract different types of entries
        all_entries = parse_result.value
        person_entries = api.filter_persons(all_entries).value
        group_entries_result = api.filter_by_objectclass(all_entries, "groupOfNames")
        group_entries = group_entries_result.value

        # Step 5: Process each type separately
        sorted_persons = api.sort_hierarchically(person_entries).value
        sorted_groups = api.sort_hierarchically(group_entries).value

        # Step 6: Generate reports (LDIF outputs)
        persons_ldif = api.write(sorted_persons).value
        groups_ldif = api.write(sorted_groups).value

        # Step 7: Validate outputs
        assert len(persons_ldif) > 0
        assert len(groups_ldif) > 0
        if "objectClass: person" not in persons_ldif:
            msg: str = f"Expected 'objectClass: person' in {persons_ldif}"
            raise AssertionError(msg)
        assert "objectClass: groupOfNames" in groups_ldif

    def _create_realistic_enterprise_data(self) -> str:
        """Create realistic enterprise LDIF data for testing."""
        return """dn: dc=corp,dc=example,dc=com
objectClass: top
objectClass: domain
dc: corp

dn: ou=departments,dc=corp,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: departments

dn: ou=engineering,ou=departments,dc=corp,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: engineering
description: Engineering Department

dn: ou=people,dc=corp,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: cn=Sarah Connor,ou=people,dc=corp,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Sarah Connor
sn: Connor
givenName: Sarah
mail: sarah.connor@corp.example.com
uid: sconnor
employeeNumber: ENG001
title: Senior Software Engineer
departmentNumber: engineering

dn: cn=Kyle Reese,ou=people,dc=corp,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Kyle Reese
sn: Reese
givenName: Kyle
mail: kyle.reese@corp.example.com
uid: kreese
employeeNumber: ENG002
title: DevOps Engineer
departmentNumber: engineering

dn: cn=engineering-team,ou=groups,dc=corp,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: engineering-team
description: Engineering team members
member: cn=Sarah Connor,ou=people,dc=corp,dc=example,dc=com
member: cn=Kyle Reese,ou=people,dc=corp,dc=example,dc=com

"""
