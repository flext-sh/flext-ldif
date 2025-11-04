"""Shared RFC 4512 parsing utilities for LDAP schema definitions.

This module provides common RFC-compliant parsing functions used by all server quirks.
Eliminates ~800+ lines of duplicated regex parsing code across 10 server implementations.

Usage:
    from flext_ldif.services.rfc_parsers import AttributeParser, RfcObjectClassParser

    # Parse attribute
    result = AttributeParser.parse_common(attr_definition)
    if result.is_success:
        parsed_data = result.unwrap()
        # Add server-specific enhancements

    # Parse objectClass
    result = RfcObjectClassParser.parse_common(oc_definition)

Architecture:
    Server quirks use these as foundations and add server-specific enhancements:
    1. Call AttributeParser.parse_common() or RfcObjectClassParser.parse_common()
    2. If successful, unwrap result and add server-specific metadata
    3. Return enhanced result with FlextResult pattern

Benefits:
    - Eliminates duplication across OID, OUD, OpenLDAP, AD, 389DS, etc.
    - Consistent RFC compliance baseline for all servers
    - Easy to maintain and extend RFC parsing logic
    - Server quirks focus on server-specific enhancements only

References:
    - RFC 4512: LDAP Directory Information Models
    - Section 4.1: Schema Definitions

"""

import re
from collections.abc import Callable, Mapping
from typing import ClassVar, TypeVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.syntax import FlextLdifSyntaxService
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)

SchemaModel = TypeVar(
    "SchemaModel",
    FlextLdifModels.SchemaAttribute,
    FlextLdifModels.SchemaObjectClass,
)


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC 4512 Compliant Server Quirks - Base Implementation for LDAP Schema/ACL/Entry Parsing.

    Transforms RFC 4512 utility parsers into concrete quirks classes extending
    FlextLdifServersBase with nested Schema, Acl, and Entry quirk implementations.
    Provides RFC-compliant implementations for use as a foundation layer that
    server-specific quirks can extend.

    Architecture:
        RFC Server provides complete RFC 4512 baseline:
        - Schema: Uses AttributeParser/ObjectClassParser for strict RFC parsing
        - Acl: RFC 4516 ACL baseline implementation
        - Entry: RFC 2849 LDIF entry handling

        Server-specific quirks extend this to add server-specific features:
        - Override can_handle_attribute/objectclass() for server-specific selection
        - Override parse_attribute/parse_objectclass() for enhanced parsing
        - Override convert_*() methods for server-specific transformations

    Design Benefits:
        - Single source of truth: RFC parsers in one module
        - Composable: Server quirks extend RFC base
        - Testable: RFC quirk is independently testable
        - Maintainable: RFC updates automatically propagate to all servers

    Inheritance Hierarchy:
        FlextLdifServersBase (abstract base)
        └── FlextLdifServersRfc (RFC 4512 baseline - concrete with all quirks)
            ├── FlextLdifServersOid (Oracle OID - extends RFC)
            ├── FlextLdifServersOud (Oracle OUD - extends RFC)
            ├── FlextLdifServersOpenLDAP (OpenLDAP - extends RFC)
            └── Other servers...

    Example:
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc_server = FlextLdifServersRfc()
        schema_quirk = rfc_server.Schema()

        # RFC quirk handles all RFC-compliant attributes/objectClasses
        if schema_quirk.can_handle_attribute(attr_def):
            result = schema_quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()
                # Use parsed attribute...

        # Parse objectClass
        result = RfcObjectClassParser.parse_common(oc_definition)

    """

    def __init__(self) -> None:
        """Initialize RFC quirks."""
        super().__init__()
        self.schema = self.Schema()
        self.acl = self.Acl()
        self.entry = self.Entry()

    # =========================================================================
    # QuirksPort Protocol Implementation (Concrete Methods for RFC)
    # =========================================================================

    def normalize_entry_to_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Return the entry as is, since it's already in RFC format."""
        return FlextResult.ok(entry)

    def denormalize_entry_from_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Return the entry as is, since RFC is the target format."""
        return FlextResult.ok(entry)

    def normalize_attribute_to_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Return the attribute as is, since it's already in RFC format."""
        return FlextResult.ok(attribute)

    def denormalize_attribute_from_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Return the attribute as is, since RFC is the target format."""
        return FlextResult.ok(attribute)

    def normalize_objectclass_to_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Return the object class as is, since it's already in RFC format."""
        return FlextResult.ok(objectclass)

    def denormalize_objectclass_from_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Return the object class as is, since RFC is the target format."""
        return FlextResult.ok(objectclass)

    def normalize_acl_to_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Return the ACL as is, since it's already in RFC format."""
        return FlextResult.ok(acl)

    def denormalize_acl_from_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Return the ACL as is, since RFC is the target format."""
        return FlextResult.ok(acl)

    server_type = FlextLdifConstants.ServerTypes.RFC
    priority = 100

    def parse_ldif_content(
        self, content: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Delegate LDIF content parsing to the nested Entry quirk."""
        return self.entry.parse_content(content)

    # =========================================================================
    # DELEGATION METHODS (for backward compatibility or internal use)
    # =========================================================================

    def can_handle_attribute(self, attribute: FlextLdifModels.SchemaAttribute) -> bool:
        """Delegate to schema instance."""
        return self.schema.can_handle_attribute(attribute)

    def can_handle_objectclass(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Delegate to schema instance."""
        return self.schema.can_handle_objectclass(objectclass)

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse RFC 4512 attribute definition by delegating to AttributeParser."""
        return FlextLdifServersRfc.AttributeParser.parse_common(
            attr_definition=attr_definition,
            case_insensitive=False,
            allow_syntax_quotes=False,
        )

    def parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self.schema.parse_objectclass(oc_definition)

    def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
        """Check if this ACL is RFC-compliant.

        The RFC quirk assumes any ACL that has been successfully parsed into
        the Acl model is handleable.

        Args:
            acl: The Acl model to check.

        Returns:
            True, as any parsed ACL is considered handleable.

        """
        return True

    def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
        """Delegate ACL parsing to the nested Acl quirk."""
        return self.acl.parse_acl(acl_line)

    def create_quirk_metadata(
        self,
        original_format: str,
        extensions: dict[str, object] | None = None,
    ) -> FlextLdifModels.QuirkMetadata:
        """Create ACL quirk metadata."""
        return FlextLdifModels.QuirkMetadata(
            quirk_type=self.acl.server_type,
            original_format=original_format,
            extensions=extensions or {},
        )

    def convert_acl_to_rfc(
        self,
        acl_data: FlextLdifModels.Acl,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert ACL to RFC-compliant format (pass-through for RFC).

        Args:
            acl_data: Acl model

        Returns:
            FlextResult with RFC-compliant Acl (unchanged)

        """
        # RFC is already RFC-compliant, return unchanged
        return FlextResult[FlextLdifModels.Acl].ok(acl_data)

    def convert_acl_from_rfc(
        self,
        acl_data: FlextLdifModels.Acl,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert ACL from RFC format (pass-through for RFC).

        Args:
            acl_data: RFC-compliant Acl model

        Returns:
            FlextResult with Acl (unchanged)

        """
        return FlextResult[FlextLdifModels.Acl].ok(acl_data)

    def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        """Write ACL to RFC-compliant string format."""
        return FlextResult[str].ok(acl_data.raw_acl)

    class AttributeParser:
        """RFC 4512 attribute definition parsing utilities.

        Parses LDAP attribute definitions according to RFC 4512 Section 4.1.2.

        Attribute Definition Format:
            ( <numeric-oid>
              [ NAME ( <name> | ( <name>+ ) ) ]
              [ DESC <description> ]
              [ OBSOLETE ]
              [ SUP <attribute-type> ]
              [ EQUALITY <matching-rule> ]
              [ ORDERING <matching-rule> ]
              [ SUBSTR <matching-rule> ]
              [ SYNTAX <syntax-oid> [ {<length>} ] ]
              [ SINGLE-VALUE ]
              [ COLLECTIVE ]
              [ NO-USER-MODIFICATION ]
              [ USAGE <usage> ]
              [ X-ORIGIN <origin> ]
            )

        Example:
            >>> attr = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            >>> result = AttributeParser.parse_common(attr)
            >>> parsed = result.unwrap()
            >>> parsed["oid"]
            '2.5.4.3'
            >>> parsed["name"]
            'cn'

        """

        # RFC 4512 attribute regex patterns
        # OID_PATTERN: ClassVar[str] = r"\(\s*([0-9.]+)"
        # NAME_PATTERN: ClassVar[str] = r"NAME\s+(?:\(\s*)?'([^']+)'"
        # DESC_PATTERN: ClassVar[str] = r"DESC\s+'([^']+)'"
        # SYNTAX_PATTERN: ClassVar[str] = r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?"
        # EQUALITY_PATTERN: ClassVar[str] = r"EQUALITY\s+(\w+)"
        # SUBSTR_PATTERN: ClassVar[str] = r"SUBSTR\s+(\w+)"
        # ORDERING_PATTERN: ClassVar[str] = r"ORDERING\s+(\w+)"
        # SUP_PATTERN: ClassVar[str] = r"SUP\s+(\w+)"
        # USAGE_PATTERN: ClassVar[str] = r"USAGE\s+(\w+)"
        # X_ORIGIN_PATTERN: ClassVar[str] = r"X-ORIGIN\s+'([^']+)'"

        @staticmethod
        def parse_common(
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition with optional lenient mode.

            Extracts all RFC 4512 standard fields from attribute definition
            and builds a SchemaAttribute Pydantic model.

            Args:
                attr_definition: RFC 4512 attribute definition string
                case_insensitive: If True, use case-insensitive NAME matching (for OID quirk)
                allow_syntax_quotes: If True, allow optional quotes in SYNTAX (for OID quirk)

            Returns:
                FlextResult with SchemaAttribute model or error message

            Example:
                >>> # Strict RFC mode (OUD)
                >>> result = AttributeParser.parse_common(
                ...     "( 2.5.4.3 NAME 'cn' DESC 'Common Name' "
                ...     "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                ... )
                >>> parsed = result.unwrap()
                >>> parsed.oid
                '2.5.4.3'

                >>> # Lenient mode (OID)
                >>> result = AttributeParser.parse_common(
                ...     "( 2.5.4.3 name 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",
                ...     case_insensitive=True,
                ...     allow_syntax_quotes=True,
                ... )
                >>> parsed = result.unwrap()
                >>> parsed.name
                'cn'

            """
            try:
                # Extract OID (required) - first element after opening parenthesis
                oid_match = re.match(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                    attr_definition,
                )
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                        "RFC attribute parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                # Extract NAME (optional, single or multiple) - use OID as fallback
                name_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_NAME, attr_definition
                )
                name = name_match.group(1) if name_match else oid

                # Extract DESC (optional)
                desc_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
                    attr_definition,
                )
                desc = desc_match.group(1) if desc_match else None

                # Extract SYNTAX (optional) with optional length constraint
                syntax_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
                    attr_definition,
                )
                syntax = syntax_match.group(1) if syntax_match else None
                # NOTE: Model uses "length" not "syntax_length"
                length = (
                    int(syntax_match.group(2))
                    if syntax_match and syntax_match.group(2)
                    else None
                )

                # Validate syntax OID format using RFC 4517 service
                syntax_validation_error: str | None = None
                if syntax is not None and syntax.strip():
                    syntax_service = FlextLdifSyntaxService()
                    validate_result = syntax_service.validate_oid(syntax)
                    if validate_result.is_failure:
                        syntax_validation_error = (
                            f"Syntax OID validation failed: {validate_result.error}"
                        )
                    elif not validate_result.unwrap():
                        syntax_validation_error = (
                            f"Invalid syntax OID format: {syntax} "
                            f"(must be numeric dot-separated format)"
                        )

                # Extract matching rules (optional)
                equality_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
                    attr_definition,
                )
                equality = equality_match.group(1) if equality_match else None

                substr_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
                    attr_definition,
                )
                substr = substr_match.group(1) if substr_match else None

                ordering_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
                    attr_definition,
                )
                ordering = ordering_match.group(1) if ordering_match else None

                # Extract flags (boolean)
                single_value = (
                    re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE,
                        attr_definition,
                    )
                    is not None
                )

                # NO-USER-MODIFICATION: Only in lenient mode (OID extracts, OUD doesn't)
                no_user_modification = False
                if case_insensitive:  # Lenient mode (OID)
                    no_user_modification = (
                        re.search(
                            FlextLdifConstants.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
                            attr_definition,
                        )
                        is not None
                    )

                # Extract SUP (optional) - superior attribute type
                sup_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
                    attr_definition,
                )
                sup = sup_match.group(1) if sup_match else None

                # Extract USAGE (optional)
                usage_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
                    attr_definition,
                )
                usage = usage_match.group(1) if usage_match else None

                # Build metadata for non-standard fields using shared utility
                metadata_extensions = FlextLdifUtilities.Parser.extract_extensions(
                    attr_definition
                )

                # Store syntax validation status from RFC 4517 service
                if syntax:
                    metadata_extensions[
                        FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                    ] = syntax_validation_error is None
                    if syntax_validation_error:
                        metadata_extensions[
                            FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                        ] = syntax_validation_error

                # Store original format for round-trip fidelity
                metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                    attr_definition.strip()
                )

                # Build QuirkMetadata if we have extensions
                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.RFC,
                        extensions=metadata_extensions,
                    )
                    if metadata_extensions
                    else None
                )

                # Build SchemaAttribute model
                attribute = FlextLdifModels.SchemaAttribute(
                    oid=oid,
                    name=name,
                    desc=desc,
                    syntax=syntax,
                    length=length,
                    equality=equality,
                    ordering=ordering,
                    substr=substr,
                    single_value=single_value,
                    no_user_modification=no_user_modification,
                    sup=sup,
                    usage=usage,
                    metadata=metadata,
                )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC attribute parsing exception")
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"RFC attribute parsing failed: {e}",
                )

    class ObjectClassParser:
        """RFC 4512 objectClass definition parsing utilities.

        Parses LDAP objectClass definitions according to RFC 4512 Section 4.1.1.

        ObjectClass Definition Format:
            ( <numeric-oid>
            [ NAME ( <name> | ( <name>+ ) ) ]
            [ DESC <description> ]
            [ OBSOLETE ]
            [ SUP <object-class> [ $ <object-class>* ] ]
            [ ( ABSTRACT | STRUCTURAL | AUXILIARY ) ]
            [ MUST ( <attribute-type> [ $ <attribute-type>* ] ) ]
            [ MAY ( <attribute-type> [ $ <attribute-type>* ] ) ]
            [ X-ORIGIN <origin> ]
            )

        Example:
            >>> oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST cn MAY ( sn $ telephoneNumber ) )"
            >>> result = RfcObjectClassParser.parse_common(oc)
            >>> parsed = result.unwrap()
            >>> parsed["kind"]
            'STRUCTURAL'
            >>> parsed["must"]
            ['cn']

        """

        # RFC 4512 objectClass regex patterns
        # OID_PATTERN: ClassVar[str] = r"\(\s*([0-9.]+)"
        # NAME_PATTERN: ClassVar[str] = r"NAME\s+(?:\(\s*)?'([^']+)'"
        # DESC_PATTERN: ClassVar[str] = r"DESC\s+'([^']+)'"
        # SUP_PATTERN: ClassVar[str] = r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))"
        # MUST_PATTERN: ClassVar[str] = r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)"
        # MAY_PATTERN: ClassVar[str] = r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)"
        # X_ORIGIN_PATTERN: ClassVar[str] = r"X-ORIGIN\s+'([^']+)'"

        @classmethod
        def parse_common(
            cls,
            oc_definition: str,
            *,
            case_insensitive: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse RFC 4512 objectClass definition with optional lenient mode.

            Extracts all RFC 4512 standard fields from objectClass definition
            and builds a SchemaObjectClass Pydantic model.

            Args:
                oc_definition: RFC 4512 objectClass definition string
                case_insensitive: If True, use case-insensitive NAME matching (for OID quirk)

            Returns:
                FlextResult with SchemaObjectClass model or error message

            Example:
                >>> # Strict RFC mode (OUD)
                >>> result = RfcObjectClassParser.parse_common(
                ...     "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL "
                ...     "MUST cn MAY ( sn $ telephoneNumber ) )"
                ... )
                >>> parsed = result.unwrap()
                >>> parsed.kind
                'STRUCTURAL'

                >>> # Lenient mode (OID)
                >>> result = RfcObjectClassParser.parse_common(
                ...     "( 2.5.6.6 name 'person' SUP top STRUCTURAL )",
                ...     case_insensitive=True,
                ... )
                >>> parsed = result.unwrap()
                >>> parsed.name
                'person'

            """
            try:
                # Extract OID (required) - first element after opening parenthesis
                oid_match = re.match(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION, oc_definition
                )
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        "RFC objectClass parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                # Extract NAME (optional) - use OID as fallback
                name_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_NAME, oc_definition
                )
                name = name_match.group(1) if name_match else oid

                # Extract DESC (optional)
                desc_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_DESC, oc_definition
                )
                desc = desc_match.group(1) if desc_match else None

                # Extract SUP (optional) - superior objectClass(es)
                # Can be single or multiple separated by $
                sup = None
                sup_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
                    oc_definition,
                )
                if sup_match:
                    sup_value = sup_match.group(1) or sup_match.group(2)
                    sup_value = sup_value.strip()

                    # Handle multiple superior classes like "organization $ organizationalUnit"
                    if "$" in sup_value:
                        # Model expects single string for sup - use first one
                        sup = next(s.strip() for s in sup_value.split("$"))
                    else:
                        sup = sup_value

                # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
                # RFC 4512: Default to STRUCTURAL if KIND is not specified
                kind_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_KIND,
                    oc_definition,
                    re.IGNORECASE,
                )
                if kind_match:
                    kind = kind_match.group(1).upper()
                else:
                    # RFC 4512 default: STRUCTURAL
                    kind = FlextLdifConstants.Schema.STRUCTURAL

                # Extract MUST attributes (optional) - required attributes
                # Can be single or multiple separated by $
                must = None
                must_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
                    oc_definition,
                )
                if must_match:
                    must_value = must_match.group(1) or must_match.group(2)
                    must_value = must_value.strip()

                    if "$" in must_value:
                        must = [m.strip() for m in must_value.split("$")]
                    else:
                        must = [must_value]

                # Extract MAY attributes (optional) - optional attributes
                # Can be single or multiple separated by $
                may = None
                may_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
                    oc_definition,
                )
                if may_match:
                    may_value = may_match.group(1) or may_match.group(2)
                    may_value = may_value.strip()

                    if "$" in may_value:
                        may = [m.strip() for m in may_value.split("$")]
                    else:
                        may = [may_value]

                # Build metadata for non-standard fields using shared utility
                metadata_extensions = FlextLdifUtilities.Parser.extract_extensions(
                    oc_definition
                )

                # Store original format for round-trip fidelity
                metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                    oc_definition.strip()
                )

                # Build QuirkMetadata if we have extensions
                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.RFC,
                        extensions=metadata_extensions,
                    )
                    if metadata_extensions
                    else None
                )

                # Build SchemaObjectClass model
                objectclass = FlextLdifModels.SchemaObjectClass(
                    oid=oid,
                    name=name,
                    desc=desc,
                    sup=sup,
                    kind=kind,
                    must=must,
                    may=may,
                    metadata=metadata,
                )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC objectClass parsing exception")
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"RFC objectClass parsing failed: {e}",
                )

    class AttributeWriter:
        """RFC 4512 attribute definition writing utilities.

        Writes LDAP attribute definitions according to RFC 4512 Section 4.1.2.
        Inverse operation of AttributeParser - builds RFC-compliant strings.

        Example:
            >>> attr_data = {
            ...     "oid": "2.5.4.3",
            ...     "name": "cn",
            ...     "desc": "Common Name",
            ...     "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            ...     "equality": "caseIgnoreMatch",
            ... }
            >>> result = RfcAttributeWriter.write_common(attr_data)
            >>> rfc_string = result.unwrap()

        """

        @staticmethod
        def write_common(
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute data to RFC 4512 format.

            Builds RFC-compliant attribute definition string from SchemaAttribute model.
            All fields are optional except OID.

            Args:
                attr_data: SchemaAttribute model (oid required)

            Returns:
                FlextResult with RFC 4512 formatted string or error message

            Example:
                >>> attr = FlextLdifModels.SchemaAttribute(
                ...     oid="2.5.4.3", name="cn", desc="Common Name"
                ... )
                >>> result = AttributeWriter.write_common(attr)
                >>> result.unwrap()
                "( 2.5.4.3 NAME 'cn' DESC 'Common Name' )"

            """
            try:
                # OID is required
                if not attr_data.oid:
                    return FlextResult[str].fail(
                        "RFC attribute writing failed: missing OID",
                    )

                parts: list[str] = [f"( {attr_data.oid}"]

                # Add NAME (optional)
                if attr_data.name:
                    parts.append(f"NAME '{attr_data.name}'")

                # Add DESC (optional)
                if attr_data.desc:
                    parts.append(f"DESC '{attr_data.desc}'")

                # Add OBSOLETE flag (optional) - check metadata extensions
                if attr_data.metadata and attr_data.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.OBSOLETE
                ):
                    parts.append("OBSOLETE")

                # Add SUP (optional)
                if attr_data.sup:
                    parts.append(f"SUP {attr_data.sup}")

                # Add matching rules (optional)
                if attr_data.equality:
                    parts.append(f"EQUALITY {attr_data.equality}")

                if attr_data.ordering:
                    parts.append(f"ORDERING {attr_data.ordering}")

                if attr_data.substr:
                    parts.append(f"SUBSTR {attr_data.substr}")

                # Add SYNTAX with optional length (optional)
                if attr_data.syntax:
                    syntax_str = str(attr_data.syntax)
                    if attr_data.length is not None:
                        syntax_str += f"{{{attr_data.length}}}"
                    parts.append(f"SYNTAX {syntax_str}")

                # Add flags (optional)
                if attr_data.single_value:
                    parts.append("SINGLE-VALUE")

                # COLLECTIVE flag from metadata extensions
                if attr_data.metadata and attr_data.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.COLLECTIVE
                ):
                    parts.append("COLLECTIVE")

                if attr_data.no_user_modification:
                    parts.append("NO-USER-MODIFICATION")

                # Add USAGE (optional)
                if attr_data.usage:
                    parts.append(f"USAGE {attr_data.usage}")

                # Add X-ORIGIN (optional) from metadata
                if attr_data.metadata and attr_data.metadata.x_origin:
                    parts.append(f"X-ORIGIN '{attr_data.metadata.x_origin}'")

                # Close definition
                parts.append(")")

                return FlextResult[str].ok(" ".join(parts))

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC attribute writing exception")
                return FlextResult[str].fail(f"RFC attribute writing failed: {e}")

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Hook for subclasses to transform attribute before writing."""
            return attr_data

        def _post_write_attribute(self, written_str: str) -> str:
            """Hook for subclasses to transform written attribute string."""
            return written_str

    class ObjectClassWriter:
        """RFC 4512 objectClass definition writing utilities.

        Writes LDAP objectClass definitions according to RFC 4512 Section 4.1.1.
        Inverse operation of RfcObjectClassParser - builds RFC-compliant strings.

        Example:
            >>> oc_data = {
            ...     "oid": "2.5.6.6",
            ...     "name": "person",
            ...     "sup": "top",
            ...     "kind": FlextLdifConstants.Schema.STRUCTURAL,
            ...     "must": ["cn"],
            ...     "may": ["sn", "telephoneNumber"],
            ... }
            >>> result = RfcObjectClassWriter.write_common(oc_data)
            >>> rfc_string = result.unwrap()

        """

        @staticmethod
        def write_common(
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass data to RFC 4512 format.

            Builds RFC-compliant objectClass definition string from SchemaObjectClass model.
            All fields are optional except OID.

            Args:
                oc_data: SchemaObjectClass model (oid required)

            Returns:
                FlextResult with RFC 4512 formatted string or error message

            Example:
                >>> oc = FlextLdifModels.SchemaObjectClass(
                ...     oid="2.5.6.6",
                ...     name="person",
                ...     kind=FlextLdifConstants.Schema.STRUCTURAL,
                ...     must=["cn"],
                ... )
                >>> result = ObjectClassWriter.write_common(oc)
                >>> result.unwrap()
                "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )"

            """
            try:
                # OID is required and must not be empty
                if not oc_data.oid:
                    return FlextResult[str].fail(
                        "RFC objectClass writing failed: missing OID",
                    )

                parts: list[str] = [f"( {oc_data.oid}"]

                # Add NAME (optional)
                if oc_data.name:
                    parts.append(f"NAME '{oc_data.name}'")

                # Add DESC (optional)
                if oc_data.desc:
                    parts.append(f"DESC '{oc_data.desc}'")

                # Add OBSOLETE flag (optional) - check metadata extensions
                if oc_data.metadata and oc_data.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.OBSOLETE
                ):
                    parts.append("OBSOLETE")

                # Add SUP (optional) - can be single string or list
                if oc_data.sup:
                    parts.append(f"SUP {oc_data.sup}")

                # Add kind (optional, defaults to STRUCTURAL per RFC)
                kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
                parts.append(str(kind))

                # Add MUST (optional) - can be single or list
                if oc_data.must:
                    if isinstance(oc_data.must, list):
                        if len(oc_data.must) == 1:
                            parts.append(f"MUST {oc_data.must[0]}")
                        else:
                            must_str = " $ ".join(oc_data.must)
                            parts.append(f"MUST ( {must_str} )")
                    else:
                        parts.append(f"MUST {oc_data.must}")

                # Add MAY (optional) - can be single or list
                if oc_data.may:
                    if isinstance(oc_data.may, list):
                        if len(oc_data.may) == 1:
                            parts.append(f"MAY {oc_data.may[0]}")
                        else:
                            may_str = " $ ".join(oc_data.may)
                            parts.append(f"MAY ( {may_str} )")
                    else:
                        parts.append(f"MAY {oc_data.may}")

                # Add X-ORIGIN (optional) from metadata
                if oc_data.metadata and oc_data.metadata.x_origin:
                    parts.append(f"X-ORIGIN '{oc_data.metadata.x_origin}'")

                # Close definition
                parts.append(")")

                return FlextResult[str].ok(" ".join(parts))

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC objectClass writing exception")
                return FlextResult[str].fail(f"RFC objectClass writing failed: {e}")

        def _transform_objectclass_for_write(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Hook for subclasses to transform objectClass before writing."""
            return oc_data

        def _post_write_objectclass(self, written_str: str) -> str:
            """Hook for subclasses to transform written objectClass string."""
            return written_str

    class SchemaConverter:
        """RFC schema conversion utilities for server-specific quirks.

        Provides shared helpers for converting between RFC and server-specific formats.
        Eliminates duplicate "copy data + set server_type" code across quirks.

        Usage:
            # In server quirk convert_attribute_from_rfc method:
            return RfcSchemaConverter.set_quirk_type(
                rfc_data,
                FlextLdifConstants.ServerTypes.OID
            )

        Benefits:
            - Eliminates ~50 lines of duplicate code across OID/OUD/OpenLDAP quirks
            - Consistent server_type handling
            - Single source of truth for RFC→Server conversion baseline
        """

        @staticmethod
        def set_quirk_type(
            model_instance: SchemaModel,
            quirk_type: str,
        ) -> FlextResult[SchemaModel]:
            """Copy schema model and set quirk_type field in metadata.

            This is the common pattern used by quirks when converting from RFC format
            to a server-specific format. Most servers use RFC-compliant formats and only
            need to tag the data with their server type.

            Args:
                model_instance: RFC-compliant schema model (Attribute or ObjectClass)
                quirk_type: Server type identifier (e.g., "oid", "oud", "openldap")

            Returns:
                FlextResult with a data copy containing the new quirk_type in metadata.

            Example:
                >>> rfc_attr = FlextLdifModels.SchemaAttribute(oid="2.5.4.3", name="cn")
                >>> result = RfcSchemaConverter.set_quirk_type(
                ...     rfc_attr, FlextLdifConstants.ServerTypes.OID
                ... )
                >>> server_attr = result.unwrap()
                >>> server_attr.metadata.quirk_type
                'oid'

            """
            try:
                # Create a deep copy to avoid mutating the original model instance.
                new_model = model_instance.model_copy(deep=True)

                if new_model.metadata is None:
                    new_model.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=quirk_type
                    )
                else:
                    new_model.metadata.quirk_type = quirk_type

                return FlextResult.ok(new_model)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult.fail(
                    f"Failed to set quirk type '{quirk_type}': {e}",
                )

    class SchemaExtractor:
        """RFC schema extraction utilities for LDIF content parsing.

        Provides shared helpers for extracting attributeTypes and objectClasses
        from LDIF content strings. Eliminates duplicate line-parsing loops
        across OID, OUD, OpenLDAP, and other server quirks.

        Usage:
            # Extract attributes from LDIF
            attributes = RfcSchemaExtractor.extract_attributes_from_lines(
                ldif_content,
                self.parse_attribute
            )

            # Extract objectClasses from LDIF
            objectclasses = RfcSchemaExtractor.extract_objectclasses_from_lines(
                ldif_content,
                self.parse_objectclass
            )

        Benefits:
            - Eliminates ~30 lines of duplicate line-parsing code per server
            - Consistent case-insensitive matching across all servers
            - Server quirks provide parse callbacks, extractor handles iteration
        """

        @staticmethod
        def extract_attributes_from_lines(
            ldif_content: str,
            parse_callback: Callable[
                [str],
                FlextResult[FlextLdifModels.SchemaAttribute],
            ],
        ) -> list[FlextLdifModels.SchemaAttribute]:
            """Extract and parse all attributeTypes from LDIF content lines.

            Iterates through LDIF lines, identifies attributeTypes definitions
            (case-insensitive), and parses them using the provided callback.

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                parse_callback: Parser function to call for each attribute definition
                            (e.g., self.parse_attribute from server quirk)

            Returns:
                List of successfully parsed attribute models

            Example:
                >>> ldif = '''
                ... attributeTypes: ( 2.5.4.3 NAME 'cn' ... )
                ... attributetypes: ( 2.5.4.4 NAME 'sn' ... )
                ... '''
                >>> attrs = RfcSchemaExtractor.extract_attributes_from_lines(
                ...     ldif, quirk.parse_attribute
                ... )
                >>> len(attrs)
                2

            """
            attributes: list[FlextLdifModels.SchemaAttribute] = []

            for raw_line in ldif_content.split("\n"):
                line = raw_line.strip()

                # Case-insensitive match: attributeTypes:, attributetypes:, etc.
                if line.lower().startswith("attributetypes:"):
                    attr_def = line.split(":", 1)[1].strip()
                    result = parse_callback(attr_def)
                    if result.is_success:
                        attributes.append(result.unwrap())

            return attributes

        @staticmethod
        def extract_objectclasses_from_lines(
            ldif_content: str,
            parse_callback: Callable[
                [str],
                FlextResult[FlextLdifModels.SchemaObjectClass],
            ],
        ) -> list[FlextLdifModels.SchemaObjectClass]:
            """Extract and parse all objectClasses from LDIF content lines.

            Iterates through LDIF lines, identifies objectClasses definitions
            (case-insensitive), and parses them using the provided callback.

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                parse_callback: Parser function to call for each objectClass definition
                            (e.g., self.parse_objectclass from server quirk)

            Returns:
                List of successfully parsed objectClass models

            Example:
                >>> ldif = '''
                ... objectClasses: ( 2.5.6.6 NAME 'person' ... )
                ... objectclasses: ( 2.5.6.7 NAME 'organizationalPerson' ... )
                ... '''
                >>> ocs = RfcSchemaExtractor.extract_objectclasses_from_lines(
                ...     ldif, quirk.parse_objectclass
                ... )
                >>> len(ocs)
                2

            """
            objectclasses: list[FlextLdifModels.SchemaObjectClass] = []

            for raw_line in ldif_content.split("\n"):
                line = raw_line.strip()

                # Case-insensitive match: objectClasses:, objectclasses:, etc.
                if line.lower().startswith("objectclasses:"):
                    oc_def = line.split(":", 1)[1].strip()
                    result = parse_callback(oc_def)
                    if result.is_success:
                        objectclasses.append(result.unwrap())

            return objectclasses

    class SchemaTransformer:
        """Shared schema transformation utilities for server-specific quirks.

        Provides generic methods for transforming attribute/objectClass fields
        in server conversions. Eliminates ~1000 lines of duplicate transformation
        logic across OID, OUD, OpenLDAP, and other server implementations.

        Design Pattern:
            Each server quirk defines Constants with server-specific transformations,
            then uses SchemaTransformer methods to apply them generically:

                class Constants:
                    MATCHING_RULE_REPLACEMENTS = {...}
                    SYNTAX_OID_REPLACEMENTS = {...}

                result = SchemaTransformer.apply_attribute_transformations(
                    attr_data,
                    server_constants=self.Constants,
                )

        Benefits:
            - Single source of truth for all transformation patterns
            - Consistent error handling across all servers
            - Eliminates 90+ lines of duplicate code per server
            - Type-safe transformations with FlextResult pattern
            - Centralized logging for debugging
        """

        @staticmethod
        def normalize_attribute_name(name: str) -> str:
            """Normalize attribute NAME field.

            Transformations:
            - Remove ;binary suffix
            - Replace underscores with hyphens (;binary and _ are Oracle OID conventions)

            Args:
                name: Original attribute name

            Returns:
                Normalized name

            """
            if not name:
                return name

            # Remove ;binary suffix (Oracle OID convention)
            if ";binary" in name:
                name = name.replace(";binary", "")
                logger.debug("Removed ;binary from NAME: %s", name)

            # Replace underscores with hyphens (RFC prefers hyphens)
            if "_" in name:
                name = name.replace("_", "-")
                logger.debug("Replaced _ with - in NAME: %s", name)

            return name

        @staticmethod
        def normalize_matching_rule(
            equality: str | None,
            substr: str | None,
            replacements: dict[str, str] | None = None,
        ) -> tuple[str | None, str | None]:
            """Normalize EQUALITY and SUBSTR matching rules.

            Transformations:
            - Fix SUBSTR rules incorrectly used in EQUALITY (common OID mistake)
            - Apply server-specific matching rule replacements
            - Ensure consistency between EQUALITY and SUBSTR rules

            Args:
                equality: Current EQUALITY rule
                substr: Current SUBSTR rule
                replacements: Dict of matching rule replacements {old: new}

            Returns:
                Tuple of (normalized_equality, normalized_substr)

            """
            if not equality:
                return equality, substr

            # Fix SUBSTR rules incorrectly used in EQUALITY field
            # Handle both 'caseIgnoreSubStringsMatch' (capital S) and
            # 'caseIgnoreSubstringsMatch' (lowercase) variations
            if equality in {"caseIgnoreSubstringsMatch", "caseIgnoreSubStringsMatch"}:
                # Move SUBSTR rule to correct SUBSTR field
                new_substr = "caseIgnoreSubstringsMatch"
                new_equality = "caseIgnoreMatch"
                logger.debug(
                    "Fixed EQUALITY field: moved substr match to SUBSTR field, "
                    "using caseIgnoreMatch for EQUALITY"
                )
                return new_equality, new_substr

            # Apply server-specific matching rule replacements
            if replacements and equality in replacements:
                original = equality
                equality = replacements[equality]
                logger.debug(
                    "Replaced matching rule %s -> %s",
                    original,
                    equality,
                )

            return equality, substr

        @staticmethod
        def normalize_syntax_oid(
            syntax: str | None,
            replacements: dict[str, str] | None = None,
        ) -> str | None:
            """Normalize SYNTAX OID field.

            Transformations:
            - Remove quotes (Oracle OID uses 'OID' format, RFC 4512 uses OID)
            - Apply server-specific syntax OID replacements
            - Validate OID format

            Args:
                syntax: Original SYNTAX OID
                replacements: Dict of syntax OID replacements {old: new}

            Returns:
                Normalized syntax OID

            """
            if not syntax:
                return syntax

            # Remove quotes if present (Oracle OID convention: '1.2.3', RFC: 1.2.3)
            if syntax.startswith("'") and syntax.endswith("'"):
                syntax = syntax[1:-1]
                logger.debug("Removed quotes from SYNTAX OID: %s", syntax)

            # Apply server-specific syntax OID replacements
            if replacements and syntax in replacements:
                original = syntax
                syntax = replacements[syntax]
                logger.debug(
                    "Replaced syntax OID %s -> %s",
                    original,
                    syntax,
                )

            return syntax

        @staticmethod
        def apply_attribute_transformations(
            attr_data: FlextLdifModels.SchemaAttribute,
            name_transform: Callable[[str], str] | None = None,
            equality_transform: (
                Callable[[str, str], tuple[str, str]] | None
            ) = None,
            syntax_transform: Callable[[str], str] | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Apply transformation pipeline to attribute.

            Generic transformation pipeline that accepts optional transformer callables
            for NAME, EQUALITY/SUBSTR, and SYNTAX fields. Allows servers to customize
            transformations via dependency injection.

            Args:
                attr_data: Attribute to transform
                name_transform: Optional callable to transform NAME field
                equality_transform: Optional callable to transform EQUALITY/SUBSTR fields
                syntax_transform: Optional callable to transform SYNTAX field

            Returns:
                FlextResult with transformed attribute

            Example:
                # Simple server with just matching rule replacements
                result = SchemaTransformer.apply_attribute_transformations(
                    attr_data,
                    equality_transform=lambda eq, sub: (
                        SchemaTransformer._normalize_matching_rule(
                            eq, sub, MyServer.Constants.MATCHING_RULE_REPLACEMENTS
                        )
                    ),
                )

                # Complex server with all transformations
                result = SchemaTransformer.apply_attribute_transformations(
                    attr_data,
                    name_transform=SchemaTransformer._normalize_attribute_name,
                    equality_transform=lambda eq, sub: (
                        SchemaTransformer._normalize_matching_rule(
                            eq, sub, MyServer.Constants.MATCHING_RULE_REPLACEMENTS
                        )
                    ),
                    syntax_transform=lambda syn: (
                        SchemaTransformer._normalize_syntax_oid(
                            syn, MyServer.Constants.SYNTAX_OID_REPLACEMENTS
                        )
                    ),
                )

            """
            try:
                # Apply transformations (or keep original if no transformer provided)
                name_value = (
                    name_transform(attr_data.name) if name_transform and attr_data.name
                    else attr_data.name
                )

                equality_value = attr_data.equality
                substr_value = attr_data.substr
                if equality_transform and equality_value:
                    equality_value, substr_value = equality_transform(
                        equality_value, substr_value
                    )

                syntax_value = (
                    syntax_transform(attr_data.syntax) if syntax_transform and attr_data.syntax
                    else attr_data.syntax
                )

                # Create new attribute model with transformed values
                transformed_attr = FlextLdifModels.SchemaAttribute(
                    name=name_value,
                    oid=attr_data.oid,
                    desc=attr_data.desc,
                    sup=attr_data.sup,
                    equality=equality_value,
                    ordering=attr_data.ordering,
                    substr=substr_value,
                    syntax=syntax_value,
                    length=attr_data.length,
                    usage=attr_data.usage,
                    single_value=attr_data.single_value,
                    no_user_modification=attr_data.no_user_modification,
                    metadata=attr_data.metadata,
                )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(transformed_attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Attribute transformation failed: {e}",
                )

        @staticmethod
        def apply_objectclass_transformations(
            oc_data: FlextLdifModels.SchemaObjectClass,
            name_transform: Callable[[str], str] | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Apply transformation pipeline to objectClass.

            Currently supports NAME field transformation only, as objectClasses
            typically don't have EQUALITY/SUBSTR/SYNTAX fields like attributes.

            Args:
                oc_data: ObjectClass to transform
                name_transform: Optional callable to transform NAME field

            Returns:
                FlextResult with transformed objectClass

            """
            try:
                # Apply name transformation (or keep original if no transformer provided)
                name_value = (
                    name_transform(oc_data.name) if name_transform and oc_data.name
                    else oc_data.name
                )

                # Create new objectClass model with transformed values
                transformed_oc = FlextLdifModels.SchemaObjectClass(
                    name=name_value,
                    oid=oc_data.oid,
                    desc=oc_data.desc,
                    sup=oc_data.sup,
                    kind=oc_data.kind,
                    must=oc_data.must,
                    may=oc_data.may,
                    metadata=oc_data.metadata,
                )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(transformed_oc)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"ObjectClass transformation failed: {e}",
                )

    class Schema(FlextLdifServersBase.Schema):
        """RFC 4512 Compliant Schema Quirk - Base Implementation."""

        class Constants:
            """RFC 4512 baseline - universal intermediate format for all conversions."""

            CANONICAL_NAME: ClassVar[str] = "rfc"
            ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])
            PRIORITY: ClassVar[int] = 100  # Lowest priority - fallback only
            CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
            CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC schema quirk.

            Args:
                server_type: Optional server type (ignored for RFC - RFC is generic)
                priority: Optional priority (ignored for RFC - uses ClassVar)
            """
            # RFC implementation uses ClassVar for server_type and priority
            # Parameters are accepted for compatibility with base.py contract
            # but are not used (RFC is generic, not server-specific)
            # RFC implementation doesn't call super() as it's the base implementation

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if attribute is RFC-compliant.

            This method is part of the quirk protocol but is more relevant for
            server-specific quirks that need to identify non-standard definitions.
            For the RFC quirk, we assume any validly parsed attribute can be handled.

            Args:
                attribute: SchemaAttribute model (unused)

            Returns:
                True, as any parsed attribute is considered handleable by the RFC base.

            """
            return True

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if objectClass is RFC-compliant.

            Similar to can_handle_attribute, the RFC quirk considers any successfully
            parsed objectClass as handleable.

            Args:
                objectclass: SchemaObjectClass model (unused)

            Returns:
                True, as any parsed objectClass is considered handleable.

            """
            return True

        def should_filter_out_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """RFC quirk does not filter attributes.

            Args:
                attribute: SchemaAttribute model (unused)

            Returns:
                False

            """
            return False

        def should_filter_out_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """RFC quirk does not filter objectClasses.

            Args:
                objectclass: SchemaObjectClass model (unused)

            Returns:
                False

            """
            return False

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition by delegating to AttributeParser."""
            return FlextLdifServersRfc.AttributeParser.parse_common(
                attr_definition=attr_definition,
                case_insensitive=False,
                allow_syntax_quotes=False,
            )

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse RFC-compliant objectClass definition by delegating to ObjectClassParser."""
            return FlextLdifServersRfc.ObjectClassParser.parse_common(
                oc_definition=oc_definition, case_insensitive=False
            )

        def convert_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert attribute to RFC-compliant format (pass-through for RFC).

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant SchemaAttribute (unchanged)

            """
            try:
                rfc_model = FlextLdifModels.SchemaAttribute(
                    oid=attr_data.oid,
                    name=attr_data.name,
                    desc=attr_data.desc,
                    syntax=attr_data.syntax,
                    equality=attr_data.equality,
                    ordering=attr_data.ordering,
                    substr=attr_data.substr,
                    single_value=attr_data.single_value,
                    sup=attr_data.sup,
                    length=attr_data.length,
                    usage=attr_data.usage,
                    metadata=None,
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_model)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Attribute→RFC conversion failed: {exc}",
                )

        def convert_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert objectClass to RFC-compliant format (pass-through for RFC).

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant SchemaObjectClass (unchanged)

            """
            try:
                rfc_model = FlextLdifModels.SchemaObjectClass(
                    oid=oc_data.oid,
                    name=oc_data.name,
                    desc=oc_data.desc,
                    sup=oc_data.sup,
                    kind=oc_data.kind,
                    must=oc_data.must,
                    may=oc_data.may,
                    metadata=None,
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_model)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"ObjectClass→RFC conversion failed: {exc}",
                )

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert attribute from RFC format (pass-through for RFC).

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert objectClass from RFC format (pass-through for RFC).

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        def _transform_objectclass_for_write(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Hook for subclasses to transform objectClass before writing."""
            return oc_data

        def _post_write_objectclass(self, written_str: str) -> str:
            """Hook for subclasses to transform written objectClass string."""
            return written_str

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Hook for subclasses to transform attribute before writing."""
            return attr_data

        def _post_write_attribute(self, written_str: str) -> str:
            """Hook for subclasses to transform written attribute string."""
            return written_str

        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC-compliant string format.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            # Type check - ensure we got a proper model object
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                return FlextResult[str].fail(
                    "write_attribute_to_rfc requires SchemaAttribute model, got "
                    f"{type(attr_data).__name__}"
                )

            # Check for original format in metadata (for perfect round-trip)
            if attr_data.metadata and attr_data.metadata.original_format:
                return FlextResult[str].ok(attr_data.metadata.original_format)

            # Transform attribute data using subclass hooks
            transformed_attr = self._transform_attribute_for_write(attr_data)

            # Write to RFC format (writer now accepts model directly)
            result = FlextLdifServersRfc.AttributeWriter.write_common(transformed_attr)

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_attribute(written_str)

                # Include attribute flags and extended attributes
                extras = []

                # Add attribute flags
                if transformed_attr.no_user_modification:
                    extras.append("NO-USER-MODIFICATION")
                if transformed_attr.single_value:
                    extras.append("SINGLE-VALUE")

                # Add X-ORIGIN from metadata if available
                if transformed_attr.metadata and transformed_attr.metadata.x_origin:
                    extras.append(f"X-ORIGIN '{transformed_attr.metadata.x_origin}'")

                # Insert all extras before closing paren
                if extras and ")" in transformed_str:
                    extras_str = " " + " ".join(extras)
                    transformed_str = transformed_str.rstrip(")") + extras_str + ")"

                return FlextResult[str].ok(transformed_str)

            return result

        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC-compliant string format.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            # Type check - ensure we got a proper model object
            if not isinstance(oc_data, FlextLdifModels.SchemaObjectClass):
                return FlextResult[str].fail(
                    "write_objectclass_to_rfc requires SchemaObjectClass model, got "
                    f"{type(oc_data).__name__}"
                )

            # Check for original format in metadata (for perfect round-trip)
            if oc_data.metadata and oc_data.metadata.original_format:
                return FlextResult[str].ok(oc_data.metadata.original_format)

            # Transform objectClass data using subclass hooks
            transformed_oc = self._transform_objectclass_for_write(oc_data)

            # Write to RFC format (writer now accepts model directly)
            result = FlextLdifServersRfc.ObjectClassWriter.write_common(transformed_oc)

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_objectclass(written_str)

                # Include extended attributes from metadata
                if (
                    transformed_oc.metadata
                    and transformed_oc.metadata.x_origin
                    and ")" in transformed_str
                ):
                    # Insert X-ORIGIN before closing paren
                    x_origin_str = f" X-ORIGIN '{transformed_oc.metadata.x_origin}'"
                    transformed_str = transformed_str.rstrip(")") + x_origin_str + ")"

                return FlextResult[str].ok(transformed_str)

            return result

    class Acl(FlextLdifServersBase.Acl):
        """RFC 4516 Compliant ACL Quirk - Base Implementation."""

        class Constants:
            """RFC 4516 baseline - universal intermediate format for all ACL conversions."""

            CANONICAL_NAME: ClassVar[str] = "rfc"
            ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])
            PRIORITY: ClassVar[int] = 100  # Lowest priority - fallback only
            CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
            CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC ACL quirk.

            Args:
                server_type: Optional server type (ignored for RFC - RFC is generic)
                priority: Optional priority (ignored for RFC - uses ClassVar)
            """
            # RFC implementation uses ClassVar for server_type and priority
            # Parameters are accepted for compatibility with base.py contract
            # but are not used (RFC is generic, not server-specific)
            # RFC implementation doesn't call super() as it's the base implementation

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Check if this ACL is RFC-compliant.

            The RFC quirk assumes any ACL that has been successfully parsed into
            the Acl model is handleable.

            Args:
                acl: The Acl model to check.

            Returns:
                True, as any parsed ACL is considered handleable.

            """
            return True

        def get_acl_attribute_name(self) -> str:
            """Get RFC-compliant ACL attribute name.

            Returns:
                The name of the attribute used for ACLs in RFC 4516.

            """
            return self.acl_attribute_name

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """RFC ACL quirk does not handle attributes.

            Args:
                attribute: SchemaAttribute model (unused)

            Returns:
                False

            """
            return False

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """RFC ACL quirk does not handle objectClasses.

            Args:
                objectclass: SchemaObjectClass model (unused)

            Returns:
                False

            """
            return False

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC-compliant ACL line.

            Args:
                acl_line: The raw ACL string from the LDIF.

            Returns:
                A FlextResult containing the Acl model.

            """
            if not acl_line or not isinstance(acl_line, str):
                return FlextResult.fail("ACL line must be a non-empty string.")

            # RFC passthrough: store the raw line in the model.
            acl_model = FlextLdifModels.Acl(
                raw_acl=acl_line,
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type=self.server_type, original_format=acl_line
                ),
            )
            return FlextResult.ok(acl_model)

        def create_quirk_metadata(
            self,
            original_format: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create ACL quirk metadata."""
            return FlextLdifModels.QuirkMetadata(
                quirk_type=self.server_type,
                original_format=original_format,
                extensions=extensions or {},
            )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL to RFC-compliant format (pass-through for RFC).

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant Acl (unchanged)

            """
            # RFC is already RFC-compliant, return unchanged
            return FlextResult[FlextLdifModels.Acl].ok(acl_data)

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL from RFC format (pass-through for RFC).

            Args:
                acl_data: RFC-compliant Acl model

            Returns:
                FlextResult with Acl (unchanged)

            """
            return FlextResult[FlextLdifModels.Acl].ok(acl_data)

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC-compliant string format."""
            return FlextResult[str].ok(acl_data.raw_acl)

    class Entry(FlextLdifServersBase.Entry):
        """RFC 2849 Compliant Entry Quirk - Base Implementation."""

        class Constants:
            """RFC 2849 baseline - universal intermediate format for all entry conversions."""

            CANONICAL_NAME: ClassVar[str] = "rfc"
            ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])
            PRIORITY: ClassVar[int] = 100  # Lowest priority - fallback only
            CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
            CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])

        server_type: ClassVar[str] = "rfc"
        priority: ClassVar[int] = 100

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC entry quirk."""
            # RFC implementation doesn't call super() as it's the base implementation

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Check if entry is RFC-compliant.

            Validates RFC 2849 and RFC 4514 compliance:
            - DN must be properly formatted (RFC 4514)
            - Entry must have objectClass attribute (LDAP requirement)
            - Attributes must be non-empty

            RFC quirk acts as the baseline handler since all LDAP entries
            must be RFC-compliant before server-specific quirks can extend them.

            Args:
                entry: Entry model to validate

            Returns:
                True if entry meets RFC baseline requirements

            """
            # RFC 4514: DN must not be empty
            if not entry.dn or not entry.dn.value:
                return False

            # RFC 2849: Attributes must be present
            if not entry.attributes or not entry.attributes.attributes:
                return False

            # LDAP requirement: Every entry must have objectClass attribute
            # Use Entry model method to check for objectClass
            return entry.has_attribute(FlextLdifConstants.DictKeys.OBJECTCLASS)

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Entry quirks don't handle attribute definitions.

            Args:
                attribute: SchemaAttribute model (unused)

            Returns:
                False - Entry quirks don't handle attributes

            """
            return False

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Entry quirks don't handle objectClass definitions.

            Args:
                objectclass: SchemaObjectClass model (unused)

            Returns:
                False - Entry quirks don't handle objectClasses

            """
            return False

        def parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string into Entry models.

            This is the PRIMARY interface - parser.py calls this with raw LDIF content.
            This method internally uses ldif3 to iterate and parse all entries.

            Implementation:
            1. Use ldif3.LDIFParser to parse LDIF content
            2. For each (dn, attrs) pair from ldif3:
               - Call parse_entry() to transform into Entry model
            3. Return list of all parsed entries

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list of parsed Entry objects

            """
            try:
                entries: list[FlextLdifModels.Entry] = []

                # Handle empty/whitespace-only content gracefully
                if not ldif_content.strip():
                    return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

                # Use shared RFC 2849-compliant LDIF parser from FlextLdifUtilities
                parsed_entries = FlextLdifUtilities.Parser.parse_ldif_lines(
                    ldif_content
                )

                # Convert parsed (dn, attrs) tuples to Entry models
                for dn, attrs in parsed_entries:
                    entry_result = self.parse_entry(dn, attrs)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except (ValueError, TypeError, AttributeError, OSError, Exception) as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse LDIF content: {e}",
                )

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model.

            Converts raw LDIF parser output (dict with bytes values) into
            an Entry model with string attributes. This is the boundary method
            that converts raw parser data to Entry models - all subsequent
            processing uses Entry models.

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser (may contain bytes values)

            Returns:
                FlextResult with parsed Entry model (ready for process_entry)

            """
            try:
                # Clean/normalize DN using DN service
                cleaned_dn = FlextLdifDnService.clean_dn(entry_dn)

                # Convert raw attributes to dict[str, list[str]] format
                # Handle bytes values from ldif3 parser
                converted_attrs: dict[str, list[str]] = {}
                for attr_name, attr_values in entry_attrs.items():
                    if isinstance(attr_values, list):
                        converted_attrs[attr_name] = [
                            value.decode("utf-8", errors="replace")
                            if isinstance(value, bytes)
                            else str(value)
                            for value in attr_values
                        ]
                    elif isinstance(attr_values, bytes):
                        converted_attrs[attr_name] = [
                            attr_values.decode("utf-8", errors="replace")
                        ]
                    else:
                        converted_attrs[attr_name] = [str(attr_values)]

                # Create LdifAttributes directly from converted_attrs
                # converted_attrs is already dict[str, list[str]]
                ldif_attrs = FlextLdifModels.LdifAttributes(attributes=converted_attrs)

                # Create Entry model using Entry.create factory method
                # This ensures proper validation and model construction
                entry_result = FlextLdifModels.Entry.create(
                    dn=cleaned_dn,
                    attributes=ldif_attrs,
                )

                if entry_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Failed to create Entry model: {entry_result.error}",
                    )

                # Get the Entry model and apply server-specific processing
                entry_model = entry_result.unwrap()
                return self.process_entry(entry_model)

            except Exception as e:
                logger.exception("RFC entry parsing exception")
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process entry with RFC baseline logic (pass-through)."""
            # For RFC, no extra processing is needed.
            return FlextResult.ok(entry)

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Return the entry as is, as it's already RFC-compliant."""
            return FlextResult.ok(entry_data)

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Return the entry as is, as it's already in the target format."""
            return FlextResult.ok(entry_data)

        def denormalize_entry_from_rfc(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert RFC Entry model to RFC format (pass-through for RFC).

            Since RFC is already the canonical format, this returns the entry unchanged.

            Args:
                entry: RFC-compliant Entry model

            Returns:
                FlextResult with Entry model (unchanged)

            """
            return FlextResult[FlextLdifModels.Entry].ok(entry)


__all__ = [
    "FlextLdifServersRfc",
]
