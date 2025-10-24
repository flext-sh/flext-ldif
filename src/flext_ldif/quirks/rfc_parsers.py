"""Shared RFC 4512 parsing utilities for LDAP schema definitions.

This module provides common RFC-compliant parsing functions used by all server quirks.
Eliminates ~800+ lines of duplicated regex parsing code across 10 server implementations.

Usage:
    from flext_ldif.quirks.rfc_parsers import RfcAttributeParser, RfcObjectClassParser

    # Parse attribute
    result = RfcAttributeParser.parse_common(attr_definition)
    if result.is_success:
        parsed_data = result.unwrap()
        # Add server-specific enhancements

    # Parse objectClass
    result = RfcObjectClassParser.parse_common(oc_definition)

Architecture:
    Server quirks use these as foundations and add server-specific enhancements:
    1. Call RfcAttributeParser.parse_common() or RfcObjectClassParser.parse_common()
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

import logging
import re
from collections.abc import Callable
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants

logger = logging.getLogger(__name__)


class RfcAttributeParser:
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
        >>> result = RfcAttributeParser.parse_common(attr)
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
    ) -> FlextResult[dict[str, object]]:
        """Parse RFC 4512 attribute definition with optional lenient mode.

        Extracts all RFC 4512 standard fields from attribute definition:
        - oid: Numeric OID (required)
        - name: Attribute name (optional, can be multiple)
        - desc: Human-readable description (optional)
        - syntax: Syntax OID (optional)
        - syntax_length: Maximum length constraint (optional)
        - equality: Equality matching rule (optional)
        - substr: Substring matching rule (optional)
        - ordering: Ordering matching rule (optional)
        - single_value: Boolean flag (default: False)
        - no_user_mod: Boolean flag (default: False)
        - obsolete: Boolean flag (default: False)
        - collective: Boolean flag (default: False)
        - sup: Superior attribute type (optional)
        - usage: Attribute usage (optional)
        - x_origin: Origin extension (optional)

        Args:
            attr_definition: RFC 4512 attribute definition string
            case_insensitive: If True, use case-insensitive NAME matching (for OID quirk)
            allow_syntax_quotes: If True, allow optional quotes in SYNTAX (for OID quirk)

        Returns:
            FlextResult with parsed attribute data or error message

        Example:
            >>> # Strict RFC mode (OUD)
            >>> result = RfcAttributeParser.parse_common(
            ...     "( 2.5.4.3 NAME 'cn' DESC 'Common Name' "
            ...     "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            ... )
            >>> parsed = result.unwrap()
            >>> parsed["oid"]
            '2.5.4.3'

            >>> # Lenient mode (OID)
            >>> result = RfcAttributeParser.parse_common(
            ...     "( 2.5.4.3 name 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",
            ...     case_insensitive=True,
            ...     allow_syntax_quotes=True,
            ... )
            >>> parsed = result.unwrap()
            >>> parsed["name"]
            'cn'

        """
        try:
            parsed_data: dict[str, object] = {}

            # Extract OID (required) - first element after opening parenthesis
            oid_match = re.match(RfcAttributeParser.OID_PATTERN, attr_definition)
            if oid_match:
                parsed_data[FlextLdifConstants.DictKeys.OID] = oid_match.group(1)
            else:
                return FlextResult[dict[str, object]].fail(
                    "RFC attribute parsing failed: missing OID"
                )

            # Extract NAME (optional, single or multiple)
            # Use case-insensitive flag if requested (OID quirk needs this)
            name_pattern = (
                r"(?i)NAME\s+(?:\(\s*)?'([^']+)'"  # OID lenient mode
                if case_insensitive
                else RfcAttributeParser.NAME_PATTERN  # RFC strict mode
            )
            name_match = re.search(name_pattern, attr_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC (optional)
            desc_match = re.search(RfcAttributeParser.DESC_PATTERN, attr_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SYNTAX (optional) with optional length constraint
            # Allow optional quotes if requested (OID quirk needs this)
            syntax_pattern = (
                r"SYNTAX\s+'?([0-9.]+)(?:\{(\d+)\})?'?"  # OID lenient mode
                if allow_syntax_quotes
                else RfcAttributeParser.SYNTAX_PATTERN  # RFC strict mode
            )
            syntax_match = re.search(syntax_pattern, attr_definition)
            if syntax_match:
                parsed_data["syntax"] = syntax_match.group(1)
                if syntax_match.group(2):  # Length constraint present
                    parsed_data["syntax_length"] = syntax_match.group(2)

            # Extract matching rules (optional)
            equality_match = re.search(
                RfcAttributeParser.EQUALITY_PATTERN, attr_definition
            )
            if equality_match:
                parsed_data["equality"] = equality_match.group(1)

            substr_match = re.search(RfcAttributeParser.SUBSTR_PATTERN, attr_definition)
            if substr_match:
                parsed_data["substr"] = substr_match.group(1)

            ordering_match = re.search(
                RfcAttributeParser.ORDERING_PATTERN, attr_definition
            )
            if ordering_match:
                parsed_data["ordering"] = ordering_match.group(1)

            # Extract flags (optional, boolean)
            # SINGLE-VALUE: Always add (both OID and OUD extract this)
            if "SINGLE-VALUE" in attr_definition:
                parsed_data["single_value"] = True
            else:
                parsed_data["single_value"] = False

            # NO-USER-MODIFICATION: Only in lenient mode (OID extracts, OUD doesn't)
            if case_insensitive:  # Lenient mode (OID)
                if "NO-USER-MODIFICATION" in attr_definition:
                    parsed_data["no_user_mod"] = True
                else:
                    parsed_data["no_user_mod"] = False

            # OBSOLETE and COLLECTIVE: Only if present (extra RFC fields)
            if "OBSOLETE" in attr_definition:
                parsed_data["obsolete"] = True

            if "COLLECTIVE" in attr_definition:
                parsed_data["collective"] = True

            # Extract SUP (optional) - superior attribute type
            sup_match = re.search(RfcAttributeParser.SUP_PATTERN, attr_definition)
            if sup_match:
                parsed_data["sup"] = sup_match.group(1)

            # Extract USAGE (optional)
            usage_match = re.search(RfcAttributeParser.USAGE_PATTERN, attr_definition)
            if usage_match:
                parsed_data["usage"] = usage_match.group(1)

            # Extract X-ORIGIN (optional) - vendor extension
            xorigin_match = re.search(
                RfcAttributeParser.X_ORIGIN_PATTERN, attr_definition
            )
            if xorigin_match:
                parsed_data["x_origin"] = xorigin_match.group(1)

            return FlextResult[dict[str, object]].ok(parsed_data)

        except Exception as e:
            logger.exception("RFC attribute parsing exception")
            return FlextResult[dict[str, object]].fail(
                f"RFC attribute parsing failed: {e}"
            )


class RfcObjectClassParser:
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

    @staticmethod
    def parse_common(
        oc_definition: str,
        *,
        case_insensitive: bool = False,
    ) -> FlextResult[dict[str, object]]:
        """Parse RFC 4512 objectClass definition with optional lenient mode.

        Extracts all RFC 4512 standard fields from objectClass definition:
        - oid: Numeric OID (required)
        - name: ObjectClass name (optional)
        - desc: Human-readable description (optional)
        - sup: Superior objectClass(es) (optional, can be multiple with $ separator)
        - kind: STRUCTURAL | AUXILIARY | ABSTRACT (default: STRUCTURAL per RFC)
        - must: Required attributes (optional, list)
        - may: Optional attributes (optional, list)
        - obsolete: Boolean flag (default: False)
        - x_origin: Origin extension (optional)

        Args:
            oc_definition: RFC 4512 objectClass definition string
            case_insensitive: If True, use case-insensitive NAME matching (for OID quirk)

        Returns:
            FlextResult with parsed objectClass data or error message

        Example:
            >>> # Strict RFC mode (OUD)
            >>> result = RfcObjectClassParser.parse_common(
            ...     "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL "
            ...     "MUST cn MAY ( sn $ telephoneNumber ) )"
            ... )
            >>> parsed = result.unwrap()
            >>> parsed["kind"]
            'STRUCTURAL'

            >>> # Lenient mode (OID)
            >>> result = RfcObjectClassParser.parse_common(
            ...     "( 2.5.6.6 name 'person' SUP top STRUCTURAL )",
            ...     case_insensitive=True,
            ... )
            >>> parsed = result.unwrap()
            >>> parsed["name"]
            'person'

        """
        try:
            parsed_data: dict[str, object] = {}

            # Extract OID (required) - first element after opening parenthesis
            oid_match = re.match(RfcObjectClassParser.OID_PATTERN, oc_definition)
            if oid_match:
                parsed_data[FlextLdifConstants.DictKeys.OID] = oid_match.group(1)
            else:
                return FlextResult[dict[str, object]].fail(
                    "RFC objectClass parsing failed: missing OID"
                )

            # Extract NAME (optional)
            # Use case-insensitive flag if requested (OID quirk needs this)
            name_pattern = (
                r"(?i)NAME\s+(?:\(\s*)?'([^']+)'"  # OID lenient mode
                if case_insensitive
                else RfcObjectClassParser.NAME_PATTERN  # RFC strict mode
            )
            name_match = re.search(name_pattern, oc_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC (optional)
            desc_match = re.search(RfcObjectClassParser.DESC_PATTERN, oc_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SUP (optional) - superior objectClass(es)
            # Can be single or multiple separated by $
            sup_match = re.search(RfcObjectClassParser.SUP_PATTERN, oc_definition)
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()

                # Handle multiple superior classes like "organization $ organizationalUnit"
                if "$" in sup_value:
                    parsed_data["sup"] = [s.strip() for s in sup_value.split("$")]
                else:
                    parsed_data["sup"] = sup_value

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            # RFC 4512: Default to STRUCTURAL if KIND is not specified
            if "STRUCTURAL" in oc_definition:
                parsed_data["kind"] = "STRUCTURAL"
            elif "AUXILIARY" in oc_definition:
                parsed_data["kind"] = "AUXILIARY"
            elif "ABSTRACT" in oc_definition:
                parsed_data["kind"] = "ABSTRACT"
            else:
                # RFC 4512 default: STRUCTURAL
                parsed_data["kind"] = "STRUCTURAL"

            # Extract MUST attributes (optional) - required attributes
            # Can be single or multiple separated by $
            must_match = re.search(RfcObjectClassParser.MUST_PATTERN, oc_definition)
            if must_match:
                must_value = must_match.group(1) or must_match.group(2)
                must_value = must_value.strip()

                if "$" in must_value:
                    parsed_data["must"] = [m.strip() for m in must_value.split("$")]
                else:
                    parsed_data["must"] = [must_value]

            # Extract MAY attributes (optional) - optional attributes
            # Can be single or multiple separated by $
            may_match = re.search(RfcObjectClassParser.MAY_PATTERN, oc_definition)
            if may_match:
                may_value = may_match.group(1) or may_match.group(2)
                may_value = may_value.strip()

                if "$" in may_value:
                    parsed_data["may"] = [m.strip() for m in may_value.split("$")]
                else:
                    parsed_data["may"] = [may_value]

            # Extract flags (optional, boolean) - only add if present
            if "OBSOLETE" in oc_definition:
                parsed_data["obsolete"] = True

            # Extract X-ORIGIN (optional) - vendor extension
            xorigin_match = re.search(
                RfcObjectClassParser.X_ORIGIN_PATTERN, oc_definition
            )
            if xorigin_match:
                parsed_data["x_origin"] = xorigin_match.group(1)

            return FlextResult[dict[str, object]].ok(parsed_data)

        except Exception as e:
            logger.exception("RFC objectClass parsing exception")
            return FlextResult[dict[str, object]].fail(
                f"RFC objectClass parsing failed: {e}"
            )


class RfcAttributeWriter:
    """RFC 4512 attribute definition writing utilities.

    Writes LDAP attribute definitions according to RFC 4512 Section 4.1.2.
    Inverse operation of RfcAttributeParser - builds RFC-compliant strings.

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
                    "RFC attribute writing failed: missing OID"
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

        except Exception as e:
            logger.exception("RFC attribute writing exception")
            return FlextResult[str].fail(f"RFC attribute writing failed: {e}")


class RfcObjectClassWriter:
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
                    "RFC objectClass writing failed: missing OID"
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

        except Exception as e:
            logger.exception("RFC objectClass writing exception")
            return FlextResult[str].fail(f"RFC objectClass writing failed: {e}")


class RfcSchemaConverter:
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
        data: dict[str, object], server_type: str
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

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to set server type '{server_type}': {e}"
            )


class RfcSchemaExtractor:
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
        parse_callback: Callable[[str], FlextResult[dict[str, object]]],
    ) -> list[dict[str, object]]:
        """Extract and parse all attributeTypes from LDIF content lines.

        Iterates through LDIF lines, identifies attributeTypes definitions
        (case-insensitive), and parses them using the provided callback.

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            parse_callback: Parser function to call for each attribute definition
                          (e.g., self.parse_attribute from server quirk)

        Returns:
            List of successfully parsed attribute dictionaries

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
        attributes: list[dict[str, object]] = []

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
        parse_callback: Callable[[str], FlextResult[dict[str, object]]],
    ) -> list[dict[str, object]]:
        """Extract and parse all objectClasses from LDIF content lines.

        Iterates through LDIF lines, identifies objectClasses definitions
        (case-insensitive), and parses them using the provided callback.

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            parse_callback: Parser function to call for each objectClass definition
                          (e.g., self.parse_objectclass from server quirk)

        Returns:
            List of successfully parsed objectClass dictionaries

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
        objectclasses: list[dict[str, object]] = []

        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()

            # Case-insensitive match: objectClasses:, objectclasses:, etc.
            if line.lower().startswith("objectclasses:"):
                oc_def = line.split(":", 1)[1].strip()
                result = parse_callback(oc_def)
                if result.is_success:
                    objectclasses.append(result.unwrap())

        return objectclasses
