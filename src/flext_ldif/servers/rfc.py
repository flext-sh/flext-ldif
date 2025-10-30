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
from collections.abc import Callable
from io import BytesIO
from typing import ClassVar

from flext_core import FlextLogger, FlextResult
from ldif3 import LDIFParser

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


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

    """

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
        OID_PATTERN: ClassVar[str] = r"\(\s*([0-9.]+)"
        NAME_PATTERN: ClassVar[str] = r"NAME\s+(?:\(\s*)?'([^']+)'"
        DESC_PATTERN: ClassVar[str] = r"DESC\s+'([^']+)'"
        SYNTAX_PATTERN: ClassVar[str] = r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?"
        EQUALITY_PATTERN: ClassVar[str] = r"EQUALITY\s+(\w+)"
        SUBSTR_PATTERN: ClassVar[str] = r"SUBSTR\s+(\w+)"
        ORDERING_PATTERN: ClassVar[str] = r"ORDERING\s+(\w+)"
        SUP_PATTERN: ClassVar[str] = r"SUP\s+(\w+)"
        USAGE_PATTERN: ClassVar[str] = r"USAGE\s+(\w+)"
        X_ORIGIN_PATTERN: ClassVar[str] = r"X-ORIGIN\s+'([^']+)'"

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
                    FlextLdifServersRfc.AttributeParser.OID_PATTERN,
                    attr_definition,
                )
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                        "RFC attribute parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                # Extract NAME (optional, single or multiple) - use OID as fallback
                name_pattern = (
                    r"(?i)NAME\s+(?:\(\s*)?'([^']+)'"  # OID lenient mode
                    if case_insensitive
                    else FlextLdifServersRfc.AttributeParser.NAME_PATTERN  # RFC strict mode
                )
                name_match = re.search(name_pattern, attr_definition)
                name = name_match.group(1) if name_match else oid

                # Extract DESC (optional)
                desc_match = re.search(
                    FlextLdifServersRfc.AttributeParser.DESC_PATTERN,
                    attr_definition,
                )
                desc = desc_match.group(1) if desc_match else None

                # Extract SYNTAX (optional) with optional length constraint
                syntax_pattern = (
                    r"SYNTAX\s+'?([0-9.]+)(?:\{(\d+)\})?'?"  # OID lenient mode
                    if allow_syntax_quotes
                    else FlextLdifServersRfc.AttributeParser.SYNTAX_PATTERN  # RFC strict mode
                )
                syntax_match = re.search(syntax_pattern, attr_definition)
                syntax = syntax_match.group(1) if syntax_match else None
                # NOTE: Model uses "length" not "syntax_length"
                length = (
                    int(syntax_match.group(2))
                    if syntax_match and syntax_match.group(2)
                    else None
                )

                # Extract matching rules (optional)
                equality_match = re.search(
                    FlextLdifServersRfc.AttributeParser.EQUALITY_PATTERN,
                    attr_definition,
                )
                equality = equality_match.group(1) if equality_match else None

                substr_match = re.search(
                    FlextLdifServersRfc.AttributeParser.SUBSTR_PATTERN,
                    attr_definition,
                )
                substr = substr_match.group(1) if substr_match else None

                ordering_match = re.search(
                    FlextLdifServersRfc.AttributeParser.ORDERING_PATTERN,
                    attr_definition,
                )
                ordering = ordering_match.group(1) if ordering_match else None

                # Extract flags (boolean)
                single_value = "SINGLE-VALUE" in attr_definition

                # NO-USER-MODIFICATION: Only in lenient mode (OID extracts, OUD doesn't)
                no_user_modification = False
                if case_insensitive:  # Lenient mode (OID)
                    no_user_modification = "NO-USER-MODIFICATION" in attr_definition

                # Extract SUP (optional) - superior attribute type
                sup_match = re.search(
                    FlextLdifServersRfc.AttributeParser.SUP_PATTERN,
                    attr_definition,
                )
                sup = sup_match.group(1) if sup_match else None

                # Extract USAGE (optional)
                usage_match = re.search(
                    FlextLdifServersRfc.AttributeParser.USAGE_PATTERN,
                    attr_definition,
                )
                usage = usage_match.group(1) if usage_match else None

                # Build metadata for non-standard fields (obsolete, collective, x_origin)
                metadata_extensions: dict[str, object] = {}

                if "OBSOLETE" in attr_definition:
                    metadata_extensions["obsolete"] = True

                if "COLLECTIVE" in attr_definition:
                    metadata_extensions["collective"] = True

                xorigin_match = re.search(
                    FlextLdifServersRfc.AttributeParser.X_ORIGIN_PATTERN,
                    attr_definition,
                )
                if xorigin_match:
                    metadata_extensions["x_origin"] = xorigin_match.group(1)

                # Store original format for round-trip fidelity
                metadata_extensions["original_format"] = attr_definition.strip()

                # Build QuirkMetadata if we have extensions
                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        server_type="rfc",
                        quirk_type="rfc",
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
        OID_PATTERN: ClassVar[str] = r"\(\s*([0-9.]+)"
        NAME_PATTERN: ClassVar[str] = r"NAME\s+(?:\(\s*)?'([^']+)'"
        DESC_PATTERN: ClassVar[str] = r"DESC\s+'([^']+)'"
        SUP_PATTERN: ClassVar[str] = r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))"
        MUST_PATTERN: ClassVar[str] = r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)"
        MAY_PATTERN: ClassVar[str] = r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)"
        X_ORIGIN_PATTERN: ClassVar[str] = r"X-ORIGIN\s+'([^']+)'"

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
                oid_match = re.match(cls.OID_PATTERN, oc_definition)
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        "RFC objectClass parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                # Extract NAME (optional) - use OID as fallback
                name_pattern = (
                    r"(?i)NAME\s+(?:\(\s*)?'([^']+)'"  # OID lenient mode
                    if case_insensitive
                    else cls.NAME_PATTERN  # RFC strict mode
                )
                name_match = re.search(name_pattern, oc_definition)
                name = name_match.group(1) if name_match else oid

                # Extract DESC (optional)
                desc_match = re.search(cls.DESC_PATTERN, oc_definition)
                desc = desc_match.group(1) if desc_match else None

                # Extract SUP (optional) - superior objectClass(es)
                # Can be single or multiple separated by $
                sup = None
                sup_match = re.search(cls.SUP_PATTERN, oc_definition)
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
                if "STRUCTURAL" in oc_definition:
                    kind = "STRUCTURAL"
                elif "AUXILIARY" in oc_definition:
                    kind = "AUXILIARY"
                elif "ABSTRACT" in oc_definition:
                    kind = "ABSTRACT"
                else:
                    # RFC 4512 default: STRUCTURAL
                    kind = "STRUCTURAL"

                # Extract MUST attributes (optional) - required attributes
                # Can be single or multiple separated by $
                must = None
                must_match = re.search(cls.MUST_PATTERN, oc_definition)
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
                may_match = re.search(cls.MAY_PATTERN, oc_definition)
                if may_match:
                    may_value = may_match.group(1) or may_match.group(2)
                    may_value = may_value.strip()

                    if "$" in may_value:
                        may = [m.strip() for m in may_value.split("$")]
                    else:
                        may = [may_value]

                # Build metadata for non-standard fields (obsolete, x_origin)
                metadata_extensions: dict[str, object] = {}

                if "OBSOLETE" in oc_definition:
                    metadata_extensions["obsolete"] = True

                xorigin_match = re.search(cls.X_ORIGIN_PATTERN, oc_definition)
                if xorigin_match:
                    metadata_extensions["x_origin"] = xorigin_match.group(1)

                # Store original format for round-trip fidelity
                metadata_extensions["original_format"] = oc_definition.strip()

                # Build QuirkMetadata if we have extensions
                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        server_type="rfc",
                        quirk_type="rfc",
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
        def write_common(attr_data: dict[str, object]) -> FlextResult[str]:
            """Write attribute data to RFC 4512 format.

            Builds RFC-compliant attribute definition string from parsed data.
            All fields are optional except OID.

            Args:
                attr_data: Dictionary with attribute fields (oid required)

            Returns:
                FlextResult with RFC 4512 formatted string or error message

            Example:
                >>> attr_data = {"oid": "2.5.4.3", "name": "cn", "desc": "Common Name"}
                >>> result = RfcAttributeWriter.write_common(attr_data)
                >>> result.unwrap()
                "( 2.5.4.3 NAME 'cn' DESC 'Common Name' )"

            """
            try:
                # OID is required
                if FlextLdifConstants.DictKeys.OID not in attr_data:
                    return FlextResult[str].fail(
                        "RFC attribute writing failed: missing OID",
                    )

                parts: list[str] = [f"( {attr_data[FlextLdifConstants.DictKeys.OID]}"]

                # Add NAME (optional)
                if "name" in attr_data:
                    parts.append(f"NAME '{attr_data['name']}'")

                # Add DESC (optional)
                if "desc" in attr_data:
                    parts.append(f"DESC '{attr_data['desc']}'")

                # Add OBSOLETE flag (optional)
                if attr_data.get("obsolete"):
                    parts.append("OBSOLETE")

                # Add SUP (optional)
                if "sup" in attr_data:
                    parts.append(f"SUP {attr_data['sup']}")

                # Add matching rules (optional)
                if "equality" in attr_data:
                    parts.append(f"EQUALITY {attr_data['equality']}")

                if "ordering" in attr_data:
                    parts.append(f"ORDERING {attr_data['ordering']}")

                if "substr" in attr_data:
                    parts.append(f"SUBSTR {attr_data['substr']}")

                # Add SYNTAX with optional length (optional)
                if "syntax" in attr_data:
                    syntax_str = str(attr_data["syntax"])
                    if "syntax_length" in attr_data:
                        syntax_str += f"{{{attr_data['syntax_length']}}}"
                    parts.append(f"SYNTAX {syntax_str}")

                # Add flags (optional)
                if attr_data.get("single_value"):
                    parts.append("SINGLE-VALUE")

                if attr_data.get("collective"):
                    parts.append("COLLECTIVE")

                if attr_data.get("no_user_mod"):
                    parts.append("NO-USER-MODIFICATION")

                # Add USAGE (optional)
                if "usage" in attr_data:
                    parts.append(f"USAGE {attr_data['usage']}")

                # Add X-ORIGIN (optional)
                if "x_origin" in attr_data:
                    parts.append(f"X-ORIGIN '{attr_data['x_origin']}'")

                # Close definition
                parts.append(")")

                return FlextResult[str].ok(" ".join(parts))

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC attribute writing exception")
                return FlextResult[str].fail(f"RFC attribute writing failed: {e}")

    class ObjectClassWriter:
        """RFC 4512 objectClass definition writing utilities.

        Writes LDAP objectClass definitions according to RFC 4512 Section 4.1.1.
        Inverse operation of RfcObjectClassParser - builds RFC-compliant strings.

        Example:
            >>> oc_data = {
            ...     "oid": "2.5.6.6",
            ...     "name": "person",
            ...     "sup": "top",
            ...     "kind": "STRUCTURAL",
            ...     "must": ["cn"],
            ...     "may": ["sn", "telephoneNumber"],
            ... }
            >>> result = RfcObjectClassWriter.write_common(oc_data)
            >>> rfc_string = result.unwrap()

        """

        @staticmethod
        def write_common(oc_data: dict[str, object]) -> FlextResult[str]:
            """Write objectClass data to RFC 4512 format.

            Builds RFC-compliant objectClass definition string from parsed data.
            All fields are optional except OID.

            Args:
                oc_data: Dictionary with objectClass fields (oid required)

            Returns:
                FlextResult with RFC 4512 formatted string or error message

            Example:
                >>> oc_data = {
                ...     "oid": "2.5.6.6",
                ...     "name": "person",
                ...     "kind": "STRUCTURAL",
                ...     "must": ["cn"],
                ... }
                >>> result = RfcObjectClassWriter.write_common(oc_data)
                >>> result.unwrap()
                "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )"

            """
            try:
                # OID is required
                if FlextLdifConstants.DictKeys.OID not in oc_data:
                    return FlextResult[str].fail(
                        "RFC objectClass writing failed: missing OID",
                    )

                parts: list[str] = [f"( {oc_data[FlextLdifConstants.DictKeys.OID]}"]

                # Add NAME (optional)
                if "name" in oc_data:
                    parts.append(f"NAME '{oc_data['name']}'")

                # Add DESC (optional)
                if "desc" in oc_data:
                    parts.append(f"DESC '{oc_data['desc']}'")

                # Add OBSOLETE flag (optional)
                if oc_data.get("obsolete"):
                    parts.append("OBSOLETE")

                # Add SUP (optional) - can be single or list
                if "sup" in oc_data:
                    sup_value = oc_data["sup"]
                    if isinstance(sup_value, list):
                        sup_str = " $ ".join(sup_value)
                        parts.append(f"SUP ( {sup_str} )")
                    else:
                        parts.append(f"SUP {sup_value}")

                # Add kind (optional, defaults to STRUCTURAL per RFC)
                kind = oc_data.get("kind", "STRUCTURAL")
                parts.append(str(kind))

                # Add MUST (optional) - can be single or list
                if "must" in oc_data:
                    must_value = oc_data["must"]
                    if isinstance(must_value, list):
                        if len(must_value) == 1:
                            parts.append(f"MUST {must_value[0]}")
                        else:
                            must_str = " $ ".join(must_value)
                            parts.append(f"MUST ( {must_str} )")
                    else:
                        parts.append(f"MUST {must_value}")

                # Add MAY (optional) - can be single or list
                if "may" in oc_data:
                    may_value = oc_data["may"]
                    if isinstance(may_value, list):
                        if len(may_value) == 1:
                            parts.append(f"MAY {may_value[0]}")
                        else:
                            may_str = " $ ".join(may_value)
                            parts.append(f"MAY ( {may_str} )")
                    else:
                        parts.append(f"MAY {may_value}")

                # Add X-ORIGIN (optional)
                if "x_origin" in oc_data:
                    parts.append(f"X-ORIGIN '{oc_data['x_origin']}'")

                # Close definition
                parts.append(")")

                return FlextResult[str].ok(" ".join(parts))

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC objectClass writing exception")
                return FlextResult[str].fail(f"RFC objectClass writing failed: {e}")

    class SchemaConverter:
        """RFC schema conversion utilities for server-specific quirks.

        Provides shared helpers for converting between RFC and server-specific formats.
        Eliminates duplicate "copy data + set server_type" code across quirks.

        Usage:
            # In server quirk convert_attribute_from_rfc method:
            return RfcSchemaConverter.set_server_type(
                rfc_data,
                FlextLdifConstants.ServerTypes.OID
            )

        Benefits:
            - Eliminates ~50 lines of duplicate code across OID/OUD/OpenLDAP quirks
            - Consistent server_type handling
            - Single source of truth for RFC→Server conversion baseline
        """

        @staticmethod
        def set_server_type(
            data: dict[str, object],
            server_type: str,
        ) -> FlextResult[dict[str, object]]:
            """Copy schema data and set server_type field.

            This is the common pattern used by quirks when converting from RFC format
            to server-specific format. Most servers use RFC-compliant formats and only
            need to tag the data with their server type.

            Args:
                data: RFC-compliant schema data (attribute or objectClass)
                server_type: Server type identifier (e.g., "oid", "oud", "openldap")

            Returns:
                FlextResult with data copy containing SERVER_TYPE field

            Example:
                >>> rfc_data = {"oid": "2.5.4.3", "name": "cn"}
                >>> result = RfcSchemaConverter.set_server_type(
                ...     rfc_data, FlextLdifConstants.ServerTypes.OID
                ... )
                >>> server_data = result.unwrap()
                >>> server_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
                'oid'

            """
            try:
                # Create copy to avoid mutating input
                result_data = dict(data)
                result_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = server_type
                return FlextResult[dict[str, object]].ok(result_data)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to set server type '{server_type}': {e}",
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

    class Schema(FlextLdifServersBase.Schema):
        """RFC 4512 Compliant Schema Quirk - Base Implementation.

        Provides RFC-compliant schema parsing using AttributeParser and
        RfcObjectClassParser as the foundation for all LDAP schema processing.

        """

        # Server identity
        server_type: ClassVar[str] = "rfc"
        priority: ClassVar[int] = 100  # Lowest priority - RFC is foundation

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC schema quirk."""
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Check if this attribute is RFC-compliant.

            RFC quirk handles all RFC-compliant attributes that start with '('.
            This is the baseline - all servers inherit from this.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                True if attribute appears RFC-compliant (starts with '(')

            """
            return bool(attr_definition.strip().startswith("("))

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Check if this objectClass is RFC-compliant.

            RFC quirk handles all RFC-compliant objectClasses that start with '('.
            This is the baseline - all servers inherit from this.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                True if objectClass appears RFC-compliant (starts with '(')

            """
            return bool(oc_definition.strip().startswith("("))

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition.

            Uses strict RFC parsing (case-sensitive) for standards compliance.
            Server-specific quirks can override for lenient parsing.

            Args:
                attr_definition: AttributeType definition string per RFC 4512

            Returns:
                FlextResult with SchemaAttribute model

            """
            # RFC strict mode: case_insensitive=False, allow_syntax_quotes=False
            return FlextLdifServersRfc.AttributeParser.parse_common(
                attr_definition,
                case_insensitive=False,
                allow_syntax_quotes=False,
            )

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse RFC 4512 objectClass definition.

            Uses strict RFC parsing (case-sensitive) for standards compliance.
            Server-specific quirks can override for lenient parsing.

            Args:
                oc_definition: ObjectClass definition string per RFC 4512

            Returns:
                FlextResult with SchemaObjectClass model

            """
            # RFC strict mode: case_insensitive=False
            return FlextLdifServersRfc.ObjectClassParser.parse_common(
                oc_definition,
                case_insensitive=False,
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
            return FlextLdifServersRfc.AttributeWriter.write_common(
                attr_data.model_dump(),
            )

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
            return FlextLdifServersRfc.ObjectClassWriter.write_common(
                oc_data.model_dump(),
            )

    class Acl(FlextLdifServersBase.Acl):
        """RFC 4516 Compliant ACL Quirk - Base Implementation.

        Provides RFC 4516 compliant ACL parsing baseline.

        """

        server_type: ClassVar[str] = "rfc"
        priority: ClassVar[int] = 100

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC ACL quirk."""
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if ACL line is RFC-compliant.

            Args:
                acl_line: ACL definition line

            Returns:
                True if line is not empty

            """
            return bool(acl_line.strip())

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC-compliant ACL line.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with Acl model

            """
            try:
                acl = FlextLdifModels.Acl(
                    raw_line=acl_line.strip(),
                    metadata=self.create_quirk_metadata(
                        original_format=acl_line.strip(),
                    ),
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"ACL parsing failed: {exc}",
                )

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
            """Write ACL to RFC-compliant string format.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            return FlextResult[str].ok(acl_data.raw_acl)

    class Entry(FlextLdifServersBase.Entry):
        """RFC 2849 Compliant Entry Quirk - Base Implementation.

        Provides RFC 2849 compliant LDIF entry handling baseline.

        """

        server_type: ClassVar[str] = "rfc"
        priority: ClassVar[int] = 100

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize RFC entry quirk."""
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_entry(
            self,
            _entry_dn: str,
            _attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Check if entry is RFC-compliant.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes dict

            Returns:
                True - RFC quirk handles all entries as baseline

            """
            return True

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

                # Parse LDIF content using ldif3
                content_bytes = ldif_content.encode("utf-8")
                with BytesIO(content_bytes) as input_stream:
                    parser = LDIFParser(input_stream)

                    # Iterate through all entries from ldif3
                    for dn, entry_attrs in parser.parse():
                        # Type narrow DN to string
                        if not isinstance(dn, str):
                            continue

                        # Delegate to parse_entry() to transform individual entry
                        entry_result = self.parse_entry(
                            entry_dn=dn,
                            entry_attrs=entry_attrs,
                        )

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
            entry_attrs: dict[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model.

            This is the core parsing method that handles RFC 2849 compliant
            LDIF entry parsing. It:
            1. Cleans DN to RFC 4514 format
            2. Converts ldif3 bytes attributes to strings
            3. Creates and validates Entry model
            4. Returns fully parsed Entry object

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes dict from LDIF parser (may contain bytes values)

            Returns:
                FlextResult with parsed Entry object (fully validated)

            """
            try:
                # Step 1: Clean DN to remove spaces around '=' (RFC 4514 compliance)
                cleaned_dn = FlextLdifDnService.clean_dn(entry_dn)

                # Step 2: Convert ldif3 bytes attributes to strings
                converted_attrs: dict[str, list[str]] = {}
                for attr_name, attr_values in entry_attrs.items():
                    if isinstance(attr_values, list):
                        converted_attrs[attr_name] = [
                            value.decode("utf-8", errors="replace")
                            if isinstance(value, bytes)
                            else str(value)
                            for value in attr_values
                        ]
                    else:
                        # Handle single value (shouldn't happen but be defensive)
                        converted_attrs[attr_name] = [
                            attr_values.decode("utf-8", errors="replace")
                            if isinstance(attr_values, bytes)
                            else str(attr_values)
                        ]

                # Step 3: Create Entry model directly with validated attributes
                entry_result = FlextLdifModels.Entry.create(
                    dn=cleaned_dn,
                    attributes=converted_attrs,
                )

                if entry_result.is_success:
                    entry = entry_result.value

                    # Step 4: Apply RFC post-processing via process_entry()
                    # This adds DN to attributes dict for output processing
                    process_result = self.process_entry(
                        entry_dn=entry.dn.value,
                        attributes=entry.attributes.attributes,
                    )

                    if process_result.is_success:
                        # Update entry with processed attributes
                        processed_attrs = process_result.unwrap()
                        typed_attrs: dict[str, list[str]] = {}
                        for key, value in processed_attrs.items():
                            if isinstance(value, list):
                                typed_attrs[key] = [str(v) for v in value]
                            else:
                                typed_attrs[key] = [str(value)]
                        entry = FlextLdifModels.Entry(
                            dn=entry.dn,
                            attributes=FlextLdifModels.LdifAttributes(
                                attributes=typed_attrs,
                            ),
                        )
                        return FlextResult[FlextLdifModels.Entry].ok(entry)
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Failed to process entry: {process_result.error}",
                    )
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create entry: {entry_result.error}",
                )

            except (ValueError, TypeError, AttributeError, Exception) as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry with RFC baseline logic (pass-through).

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes dict

            Returns:
                FlextResult with processed entry attributes including DN

            """
            # Add DN to attributes for write_entry_to_ldif()
            processed = dict(attributes)
            processed[FlextLdifConstants.DictKeys.DN] = entry_dn
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(processed)

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry to RFC-compliant format (pass-through for RFC).

            Args:
                entry_data: Server-specific entry attributes dict

            Returns:
                FlextResult with RFC-compliant entry attributes (unchanged)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(entry_data)

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry from RFC format (pass-through for RFC).

            Args:
                entry_data: RFC-compliant entry attributes dict

            Returns:
                FlextResult with entry attributes (unchanged)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(entry_data)

        def write_entry_to_ldif(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[str]:
            """Write RFC entry data to standard LDIF format string.

            Args:
                entry_data: Entry attributes dict (must include 'dn' key)

            Returns:
                FlextResult with LDIF formatted entry string

            """
            try:
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail("Missing required DN field")

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Write all attributes except DN and internal fields
                for attr_name, attr_values in entry_data.items():
                    if (
                        attr_name.startswith("_")
                        or attr_name == FlextLdifConstants.DictKeys.DN
                    ):
                        continue

                    if isinstance(attr_values, list):
                        ldif_lines.extend(
                            f"{attr_name}: {value}" for value in attr_values
                        )
                    else:
                        ldif_lines.append(f"{attr_name}: {attr_values}")

                ldif_text = "\n".join(ldif_lines) + "\n"
                return FlextResult[str].ok(ldif_text)

            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                return FlextResult[str].fail(f"Failed to write entry to LDIF: {exc}")


__all__ = [
    "FlextLdifServersRfc",
]
