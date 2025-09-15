"""Test edge cases in services.py to improve coverage.

This test file targets specific uncovered lines in services.py
to achieve the required 90% coverage threshold.
"""

from flext_ldif.services import FlextLDIFServices


class TestServicesEdgeCases:
    """Test edge cases for services.py coverage."""

    def test_parser_validate_syntax_empty_content(self) -> None:
        """Test parser validate_syntax with empty content."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test empty content
        result = parser.validate_ldif_syntax("")
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Empty LDIF content" in error_message

    def test_parser_validate_syntax_whitespace_only(self) -> None:
        """Test parser validate_syntax with whitespace only."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test whitespace only content
        result = parser.validate_ldif_syntax("   \n  \t  \n  ")
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Empty LDIF content" in error_message

    def test_parser_validate_syntax_no_lines(self) -> None:
        """Test parser validate_syntax with no lines."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test content that results in no lines after split
        result = parser.validate_ldif_syntax("\n\n\n")
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Empty LDIF content" in error_message

    def test_parser_validate_syntax_invalid_start(self) -> None:
        """Test parser validate_syntax with invalid start."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test content that doesn't start with dn:
        result = parser.validate_ldif_syntax("cn: test\nobjectClass: person")
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "LDIF must start with dn:" in error_message

    def test_parser_validate_syntax_valid_content(self) -> None:
        """Test parser validate_syntax with valid content."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test valid LDIF content
        valid_ldif = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person"
        result = parser.validate_ldif_syntax(valid_ldif)
        assert result.is_success
        assert result.value is True

    def test_parser_validate_syntax_exception_handling(self) -> None:
        """Test parser validate_syntax exception handling."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test with content that might cause issues
        result = parser.validate_ldif_syntax("test content")
        # This should fail due to invalid format, not exception
        assert result.is_failure
        assert result.error is not None

    def test_validator_get_config_info(self) -> None:
        """Test validator get_config_info method."""
        services = FlextLDIFServices()
        validator = services.validator

        config_info = validator.get_config_info()
        assert isinstance(config_info, dict)
        assert "config" in config_info
        assert "service" in config_info

    def test_writer_get_config_info(self) -> None:
        """Test writer get_config_info method."""
        services = FlextLDIFServices()
        writer = services.writer

        config_info = writer.get_config_info()
        assert isinstance(config_info, dict)
        assert "config" in config_info
        assert "service" in config_info

    def test_analytics_get_config_info(self) -> None:
        """Test analytics get_config_info method."""
        services = FlextLDIFServices()
        analytics = services.analytics

        config_info = analytics.get_config_info()
        assert isinstance(config_info, dict)
        assert "config" in config_info
        assert "service" in config_info

    def test_transformer_get_config_info(self) -> None:
        """Test transformer get_config_info method."""
        services = FlextLDIFServices()
        transformer = services.transformer

        config_info = transformer.get_config_info()
        assert isinstance(config_info, dict)
        assert "config" in config_info
        assert "service" in config_info

    def test_repository_get_config_info(self) -> None:
        """Test repository get_config_info method."""
        services = FlextLDIFServices()
        repository = services.repository

        config_info = repository.get_config_info()
        assert isinstance(config_info, dict)
        assert "config" in config_info
        assert "service" in config_info

    def test_services_nested_classes_initialization(self) -> None:
        """Test nested classes initialization."""
        services = FlextLDIFServices()

        # Test all nested classes are properly initialized
        assert services.parser is not None
        assert services.validator is not None
        assert services.writer is not None
        assert services.analytics is not None
        assert services.transformer is not None
        assert services.repository is not None

    def test_services_nested_classes_config_access(self) -> None:
        """Test nested classes config access."""
        services = FlextLDIFServices()

        # Test config access from nested classes
        parser_config = services.parser.get_config_info()
        validator_config = services.validator.get_config_info()
        writer_config = services.writer.get_config_info()
        analytics_config = services.analytics.get_config_info()
        transformer_config = services.transformer.get_config_info()
        repository_config = services.repository.get_config_info()

        assert isinstance(parser_config, dict)
        assert isinstance(validator_config, dict)
        assert isinstance(writer_config, dict)
        assert isinstance(analytics_config, dict)
        assert isinstance(transformer_config, dict)
        assert isinstance(repository_config, dict)

    def test_services_comprehensive_workflow(self) -> None:
        """Test comprehensive services workflow."""
        services = FlextLDIFServices()

        # Test complete workflow
        # 1. Validate syntax
        valid_ldif = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person"
        syntax_result = services.parser.validate_ldif_syntax(valid_ldif)
        assert syntax_result.is_success

        # 2. Get config info from all services
        parser_config = services.parser.get_config_info()
        validator_config = services.validator.get_config_info()
        writer_config = services.writer.get_config_info()
        analytics_config = services.analytics.get_config_info()
        transformer_config = services.transformer.get_config_info()
        repository_config = services.repository.get_config_info()

        # 3. Execute main service
        execute_result = services.execute()
        assert execute_result.is_success

        # Verify all results
        assert syntax_result.is_success
        assert execute_result.is_success
        assert all(
            isinstance(config, dict)
            for config in [
                parser_config,
                validator_config,
                writer_config,
                analytics_config,
                transformer_config,
                repository_config,
            ]
        )

    def test_services_error_scenarios(self) -> None:
        """Test various error scenarios."""
        services = FlextLDIFServices()

        # Test various invalid inputs
        invalid_inputs = [
            "",  # Empty
            "   ",  # Whitespace only
            "\n\n\n",  # Newlines only
            "cn: test",  # No dn:
            "invalid content",  # Invalid format
        ]

        for invalid_input in invalid_inputs:
            result = services.parser.validate_ldif_syntax(invalid_input)
            assert result.is_failure
            assert result.error is not None

    def test_services_config_consistency(self) -> None:
        """Test configuration consistency across services."""
        services = FlextLDIFServices()

        # All nested services should have consistent config access
        configs = [
            services.parser.get_config_info(),
            services.validator.get_config_info(),
            services.writer.get_config_info(),
            services.analytics.get_config_info(),
            services.transformer.get_config_info(),
            services.repository.get_config_info(),
        ]

        # All should be dictionaries
        assert all(isinstance(config, dict) for config in configs)

        # All should have some content
        assert all(len(config) > 0 for config in configs)
