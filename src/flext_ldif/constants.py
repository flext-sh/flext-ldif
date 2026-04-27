"""LDIF constants and enumerations."""

from __future__ import annotations

from collections.abc import (
    Mapping,
)
from enum import StrEnum, unique
from types import MappingProxyType
from typing import ClassVar, Final

from flext_cli import FlextCliConstants, t
from flext_ldif import FlextLdifConstantsBase, FlextLdifConstantsEnums


class FlextLdifConstants(FlextCliConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(FlextLdifConstantsBase, FlextLdifConstantsEnums):
        """LDIF domain constants namespace."""

        BINARY_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset({
            "usercertificate",
            "cacertificate",
            "certificaterevocationlist",
            "authorityrevocationlist",
            "crosscertificatepair",
            "photo",
            "jpegphoto",
            "audio",
            "userpkcs12",
            "usersmimecertificate",
            "thumbnailphoto",
            "thumbnaillogo",
            "objectguid",
            "objectsid",
        })

        OBJECTCLASS_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset({
            FlextLdifConstantsEnums.ServerTypes.OID.value,
            FlextLdifConstantsEnums.ServerTypes.OUD.value,
            FlextLdifConstantsEnums.ServerTypes.AD.value,
            FlextLdifConstantsEnums.ServerTypes.DS389.value,
            "novell_edirectory",
            FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI.value,
        })
        NAMING_ATTR_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset({
            FlextLdifConstantsEnums.ServerTypes.OID.value,
            FlextLdifConstantsEnums.ServerTypes.OUD.value,
            FlextLdifConstantsEnums.ServerTypes.AD.value,
        })
        BINARY_OPTION_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset({
            FlextLdifConstantsEnums.ServerTypes.OPENLDAP.value,
            FlextLdifConstantsEnums.ServerTypes.OID.value,
            FlextLdifConstantsEnums.ServerTypes.OUD.value,
        })

        DEFAULT_ACL_ATTRIBUTES: Final[t.StrSequence] = (
            "acl",
            "aci",
            "olcAccess",
        )

        ALL_DN_VALUED: Final[frozenset[str]] = frozenset({
            "member",
            "uniqueMember",
            "owner",
            "managedBy",
            "manager",
            "secretary",
            "seeAlso",
            "parent",
            "refersTo",
            "memberOf",
            "groups",
            "authorizedTo",
            "hasSubordinates",
            "subordinateDn",
        })

        OID_TRUE: Final[str] = "1"
        OID_FALSE: Final[str] = "0"

        OID_BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset({
            "orclisenabled",
            "orclaccountlocked",
            "orclpwdmustchange",
            "orclpasswordverify",
            "orclisvisible",
            "orclsamlenable",
            "orclsslenable",
            "orcldasenableproductlogo",
            "orcldasenablesubscriberlogo",
            "orcldasshowproductlogo",
            "orcldasenablebranding",
            "orcldasisenabled",
            "orcldasismandatory",
            "orcldasispersonal",
            "orcldassearchable",
            "orcldasselfmodifiable",
            "orcldasviewable",
            "orcldasREDACTED_LDAP_BIND_PASSWORDmodifiable",
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
        })

        OID_TO_RFC_BOOL: Final[t.StrMapping] = MappingProxyType({
            OID_TRUE: FlextLdifConstantsBase.TRUE_RFC,
            OID_FALSE: FlextLdifConstantsBase.FALSE_RFC,
            "true": FlextLdifConstantsBase.TRUE_RFC,
            "false": FlextLdifConstantsBase.FALSE_RFC,
        })
        RFC_TO_OID_BOOL: Final[t.StrMapping] = MappingProxyType({
            FlextLdifConstantsBase.TRUE_RFC: OID_TRUE,
            FlextLdifConstantsBase.FALSE_RFC: OID_FALSE,
            "true": OID_TRUE,
            "false": OID_FALSE,
        })

        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: Final[t.StrMapping] = MappingProxyType({
            "orclguid": "entryUUID",
            "orclaci": "aci",
            "orclentrylevelaci": "aci",
        })
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: Final[t.StrMapping] = MappingProxyType({
            "entryUUID": "orclguid",
            "aci": "orclaci",
        })
        ACL_PERMISSION_KEYS: Final[tuple[str, ...]] = (
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
            "browse",
            "auth",
            "all",
        )

        VALID_SERVER_TYPES: Final[frozenset[str]] = frozenset(
            server_type.value for server_type in FlextLdifConstantsEnums.ServerTypes
        )

        CLASS_SUFFIXES: Final[tuple[str, ...]] = ("Acl", "Schema", "Entry", "Constants")

        OID_TO_NAME: ClassVar[t.StrMapping] = MappingProxyType({
            "2.5.5.5": "integer",
            "1.3.6.1.4.1.1466.115.121.1.1": "aci",
            "1.3.6.1.4.1.1466.115.121.1.2": "access_point",
            "1.3.6.1.4.1.1466.115.121.1.3": "attribute_type_description",
            "1.3.6.1.4.1.1466.115.121.1.4": "audio",
            "1.3.6.1.4.1.1466.115.121.1.5": "binary",
            "1.3.6.1.4.1.1466.115.121.1.6": "bit_string",
            "1.3.6.1.4.1.1466.115.121.1.7": "boolean",
            "1.3.6.1.4.1.1466.115.121.1.8": "certificate",
            "1.3.6.1.4.1.1466.115.121.1.9": "certificate_list",
            "1.3.6.1.4.1.1466.115.121.1.10": "certificate_pair",
            "1.3.6.1.4.1.1466.115.121.1.11": "country_string",
            "1.3.6.1.4.1.1466.115.121.1.12": "dn",
            "1.3.6.1.4.1.1466.115.121.1.13": "data_quality_syntax",
            "1.3.6.1.4.1.1466.115.121.1.14": "delivery_method",
            "1.3.6.1.4.1.1466.115.121.1.15": "directory_string",
            "1.3.6.1.4.1.1466.115.121.1.16": "dit_content_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.17": "dit_structure_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.18": "dlexp_time",
            "1.3.6.1.4.1.1466.115.121.1.19": "dn_with_binary",
            "1.3.6.1.4.1.1466.115.121.1.20": "dn_with_string",
            "1.3.6.1.4.1.1466.115.121.1.21": "directory_string",
            "1.3.6.1.4.1.1466.115.121.1.22": "enhanced_guide",
            "1.3.6.1.4.1.1466.115.121.1.23": "facsimile_telephone_number",
            "1.3.6.1.4.1.1466.115.121.1.24": "fax",
            "1.3.6.1.4.1.1466.115.121.1.25": "generalized_time",
            "1.3.6.1.4.1.1466.115.121.1.26": "guide",
            "1.3.6.1.4.1.1466.115.121.1.27": "ia5_string",
            "1.3.6.1.4.1.1466.115.121.1.28": "jpeg",
            "1.3.6.1.4.1.1466.115.121.1.29": "ldap_syntax_description",
            "1.3.6.1.4.1.1466.115.121.1.30": "matching_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.31": "matching_rule_use_description",
            "1.3.6.1.4.1.1466.115.121.1.32": "mhs_or_address",
            "1.3.6.1.4.1.1466.115.121.1.33": "modify_increment",
            "1.3.6.1.4.1.1466.115.121.1.34": "name_and_optional_uid",
            "1.3.6.1.4.1.1466.115.121.1.35": "name_form_description",
            "1.3.6.1.4.1.1466.115.121.1.36": "numeric_string",
            "1.3.6.1.4.1.1466.115.121.1.37": "object_class_description",
            "1.3.6.1.4.1.1466.115.121.1.38": "oid",
            "1.3.6.1.4.1.1466.115.121.1.39": "octet_string",
            "1.3.6.1.4.1.1466.115.121.1.40": "other_mailbox",
            "1.3.6.1.4.1.1466.115.121.1.41": "postal_address",
            "1.3.6.1.4.1.1466.115.121.1.42": "protocol_information",
            "1.3.6.1.4.1.1466.115.121.1.43": "presentation_address",
            "1.3.6.1.4.1.1466.115.121.1.44": "printable_string",
            "1.3.6.1.4.1.1466.115.121.1.50": "telephone_number",
            "1.3.6.1.4.1.1466.115.121.1.51": "teletex_terminal_identifier",
            "1.3.6.1.4.1.1466.115.121.1.52": "telex_number",
            "1.3.6.1.4.1.1466.115.121.1.53": "time_of_day",
            "1.3.6.1.4.1.1466.115.121.1.54": "utctime",
            "1.3.6.1.4.1.1466.115.121.1.55": "utf8_string",
            "1.3.6.1.4.1.1466.115.121.1.56": "unicode_string",
            "1.3.6.1.4.1.1466.115.121.1.57": "uui",
            "1.3.6.1.4.1.1466.115.121.1.58": "substring_assertion",
        })
        NAME_TO_OID: Final[t.StrMapping] = MappingProxyType({
            v: k for k, v in OID_TO_NAME.items()
        })
        NAME_TO_TYPE_CATEGORY: Final[t.StrMapping] = MappingProxyType({
            "integer": "integer",
            "boolean": "boolean",
            "distinguished_name": "dn",
            "dn": "dn",
            "generalized_time": "time",
            "utc_time": "time",
            "binary": "binary",
            "octet_string": "binary",
            "directory_string": "string",
            "ia5_string": "string",
            "printable_string": "string",
            "numeric_string": "string",
            "telephone_number": "string",
            "mail_preference": "string",
            "other_mailbox": "string",
            "postal_address": "string",
            "country_string": "string",
            "dn_qualifier": "string",
            "certificate": "binary",
            "certificate_list": "binary",
            "certificate_pair": "binary",
            "supported_algorithm": "binary",
            "dsa_quality": "string",
            "data_quality_syntax": "binary",
            "dsi_mods": "binary",
            "entry_information_information": "binary",
            "facsimile_telephone_number": "string",
            "fax": "binary",
            "jpeg": "binary",
            "master_and_shadow_access_points": "dn",
            "name_and_optional_uid": "string",
            "name_forms": "string",
            "nis_netgroup_triple": "string",
            "object_class_description": "string",
            "oid": "string",
            "presentation_address": "binary",
            "protocol_information": "binary",
            "substring_assertion": "string",
            "teletex_terminal_identifier": "string",
            "telex_number": "string",
            "unique_member": "dn",
            "user_password": "binary",
            "user_certificate": "binary",
            "ca_certificate": "binary",
            "authority_revocation_list": "binary",
            "certificate_revocation_list": "binary",
            "cross_certificate_pair": "binary",
            "delta_revocation_list": "binary",
            "dit_content_rule_description": "string",
            "dit_structure_rule_description": "string",
            "dse_type": "string",
            "ldap_syntax_description": "string",
            "matching_rule_description": "string",
            "matching_rule_use_description": "string",
            "name_form_description": "string",
            "subschema": "binary",
            "access_point": "dn",
            "attribute_type_description": "string",
            "audio": "binary",
            "bit_string": "string",
            "aci": "string",
            "utf8_string": "string",
            "unicode_string": "string",
            "uui": "string",
        })
        COMMON_SYNTAXES: Final[frozenset[str]] = frozenset({
            "1.3.6.1.4.1.1466.115.121.1.7",
            "1.3.6.1.4.1.1466.115.121.1.12",
            "1.3.6.1.4.1.1466.115.121.1.15",
            "1.3.6.1.4.1.1466.115.121.1.24",
            "1.3.6.1.4.1.1466.115.121.1.26",
            "1.3.6.1.4.1.1466.115.121.1.27",
            "1.3.6.1.4.1.1466.115.121.1.36",
            "1.3.6.1.4.1.1466.115.121.1.38",
            "1.3.6.1.4.1.1466.115.121.1.40",
            "1.3.6.1.4.1.1466.115.121.1.44",
            "1.3.6.1.4.1.1466.115.121.1.50",
        })
        SYNTAX_VALID_BOOLEAN_VALUES: Final[frozenset[str]] = frozenset({
            "TRUE",
            "FALSE",
        })

        @unique
        class EntryCriteriaMode(StrEnum):
            """Matching strategy for entry criteria evaluation."""

            ANY = "any"
            ALL = "all"

        @unique
        class SchemaItemKind(StrEnum):
            """Schema item discriminator used in conversion flows."""

            ATTRIBUTE = "attribute"
            OBJECTCLASS = "objectclass"

        @unique
        class NormalizeFallback(StrEnum):
            """Fallback strategy when DN normalization fails."""

            LOWER = "lower"
            UPPER = "upper"
            ORIGINAL = "original"

        DEFAULT_ENCODING: Final[str] = FlextLdifConstantsEnums.Encoding.UTF8.value
        DEFAULT_STRICT_VALIDATION: Final[bool] = True

        SERVER_TYPE_ALIASES: Final[
            Mapping[str, FlextLdifConstantsEnums.ServerTypes]
        ] = MappingProxyType({
            "active_directory": FlextLdifConstantsEnums.ServerTypes.AD,
            "activedirectory": FlextLdifConstantsEnums.ServerTypes.AD,
            "oracle_oid": FlextLdifConstantsEnums.ServerTypes.OID,
            "oracleoid": FlextLdifConstantsEnums.ServerTypes.OID,
            "oracle_oud": FlextLdifConstantsEnums.ServerTypes.OUD,
            "oracleoud": FlextLdifConstantsEnums.ServerTypes.OUD,
            "openldap": FlextLdifConstantsEnums.ServerTypes.OPENLDAP2,
            "openldap1": FlextLdifConstantsEnums.ServerTypes.OPENLDAP1,
            "openldap2": FlextLdifConstantsEnums.ServerTypes.OPENLDAP2,
            "ibm_tivoli": FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
            "ibmtivoli": FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
            "tivoli": FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
            "novell_edirectory": FlextLdifConstantsEnums.ServerTypes.NOVELL,
            "novelledirectory": FlextLdifConstantsEnums.ServerTypes.NOVELL,
            "edirectory": FlextLdifConstantsEnums.ServerTypes.NOVELL,
            "apache_directory": FlextLdifConstantsEnums.ServerTypes.APACHE,
            "apachedirectory": FlextLdifConstantsEnums.ServerTypes.APACHE,
            "apacheds": FlextLdifConstantsEnums.ServerTypes.APACHE,
            "389ds": FlextLdifConstantsEnums.ServerTypes.DS389,
            "389directory": FlextLdifConstantsEnums.ServerTypes.DS389,
        })

        class EntryDefaults:
            """Entry processing default values (RFC 2849 LDIF domain)."""

            UNKNOWN_VALUE = "unknown"
            ASCII_THRESHOLD = 127

        class OperationalAttributes:
            """Operational attributes to ignore in LDIF entry processing."""

            IGNORE_SET: ClassVar[frozenset[str]] = frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryUUID",
                "entryCSN",
                "hasSubordinates",
                "numSubordinates",
                "subschemaSubentry",
                "dseType",
            })

        @unique
        class LogLevelLower(StrEnum):
            """Lowercase log-level names for logger dispatch comparisons."""

            DEBUG = "debug"
            INFO = "info"
            WARNING = "warning"
            ERROR = "error"
            CRITICAL = "critical"


c = FlextLdifConstants

__all__: list[str] = ["FlextLdifConstants", "c"]
