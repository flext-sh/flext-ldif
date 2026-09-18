# from flext-ldif_docs/getting-started.md:337
from flext_ldif import ldif, FlextLdifSettings

ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: inetOrgPerson
cn: test"""

settings = FlextLdifSettings(ldif_strict_validation=True)
api = ldif(settings=settings)

# Parse with strict validation
result = api.parse_string(ldif_content)
if result.success:
    entries = result.unwrap().entries

    # Validate all entries
    validation_result = api.validate_entries(entries)
    if validation_result.failure:
        print(f"Validation issues found: {validation_result.error}")
    else:
        report = validation_result.unwrap()
        # Continue processing valid entries
        print(
            f"Processing {report.valid_entries} valid entries "
            f"out of {report.total_entries} total entries"
        )```
## Troubleshooting

### Common Issues

**Memory Issues with Large Files**:

- Current version loads entire LDIF into memory
- For files >100MB, consider processing in smaller chunks
- Monitor memory usage during processing

**Parse Errors**:

- Verify LDIF format compliance (RFC 2849)
- Check character encoding (UTF-8 recommended)
- Enable debug logging for detailed error information

**Type Checking Issues**:

- Ensure Python 3.13+ is being used
- Verify all dependencies are properly installed
- Run `make type-check` to identify issues (uses Pyrefly strict mode)
- Check PYTHONPATH=src is set for all operations

### Getting Help

- **Documentation**: Complete documentation
- **API Reference**: API documentation
- **Examples**: Usage examples
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

## Next Steps

Once you have FLEXT-LDIF installed and working:

1. **Architecture**: Understand the service-oriented design
1. **API Reference**: Explore all available operations
1. **Examples**: See practical usage patterns
1. **Integration**: Learn about FLEXT ecosystem integration

## Related Documentation

**Within Project**:

- Architecture - Service-oriented design and RFC-first approach
- API Reference - Complete API documentation
- Configuration - Settings and environment management
- Development - Contributing and workflows
- Integration Guide - FLEXT ecosystem integration

**Across Projects**:

- [flext-core Foundation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/guides/railway-oriented-programming.md) - Railway-oriented programming patterns
- [flext-ldap Integration](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-ldap/docs/guides/integration.md) - LDAP operations integration

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

______________________________________________________________________

This getting started guide provides the foundation for using FLEXT-LDIF effectively within the FLEXT ecosystem while maintaining software development practices.
