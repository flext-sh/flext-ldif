"""LDIF constants and enumerations."""

from __future__ import annotations

import struct
from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from flext_cli import c
from flext_ldif._constants.acl_convert import FlextLdifConstantsAclConvert
from flext_ldif._constants.acl_convert_oud import FlextLdifConstantsAclConvertOud
from flext_ldif._constants.base import FlextLdifConstantsBase
from flext_ldif._constants.enums import FlextLdifConstantsEnums

if TYPE_CHECKING:
    from flext_cli import t


class FlextLdifConstants(c):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif(
        FlextLdifConstantsBase,
        FlextLdifConstantsEnums,
        FlextLdifConstantsAclConvert,
        FlextLdifConstantsAclConvertOud,
    ):
        """LDIF domain constants namespace."""

        EXC_LDIF_PARSE: Final[tuple[type[Exception], ...]] = (
            AttributeError,
            KeyError,
            UnicodeDecodeError,
            ValueError,
            struct.error,
        )
        """LDIF parsing boundary catch: attribute access, dict, unicode,
        type, and struct unpacking errors raised during entry parsing."""

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

        SERVER_VALIDATION_CAPABILITIES: Final[
            t.MappingKV[FlextLdifConstantsEnums.ServerTypes, frozenset[str]]
        ] = MappingProxyType({
            FlextLdifConstantsEnums.ServerTypes.OID: frozenset({
                "requires_objectclass",
                "requires_naming_attr",
                "requires_binary_option",
            }),
            FlextLdifConstantsEnums.ServerTypes.OUD: frozenset({
                "requires_objectclass",
                "requires_naming_attr",
                "requires_binary_option",
            }),
            FlextLdifConstantsEnums.ServerTypes.OPENLDAP: frozenset({
                "requires_binary_option"
            }),
            FlextLdifConstantsEnums.ServerTypes.OPENLDAP2: frozenset({
                "requires_binary_option"
            }),
            FlextLdifConstantsEnums.ServerTypes.AD: frozenset({
                "requires_objectclass",
                "requires_naming_attr",
            }),
            FlextLdifConstantsEnums.ServerTypes.DS389: frozenset({
                "requires_objectclass"
            }),
            FlextLdifConstantsEnums.ServerTypes.NOVELL: frozenset({
                "requires_objectclass"
            }),
            FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI: frozenset({
                "requires_objectclass"
            }),
        })

        DEFAULT_ACL_ATTRIBUTES: Final[t.StrSequence] = ("acl", "aci", "olcAccess")

        RFC_ACL_ATTRIBUTES: Final[t.StrSequence] = (
            "aci",
            "acl",
            "olcAccess",
            "aclRights",
            "aclEntry",
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
        ACL_PERMISSION_KEYS: Final[t.StrSequence] = (
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
        DETECTION_PATTERN_ATTR: Final[str] = "DETECTION_PATTERN"
        DETECTION_OID_PATTERN_ATTR: Final[str] = "DETECTION_OID_PATTERN"
        DETECTION_ACTIVE_DIRECTORY_ATTRIBUTE: Final[str] = "samaccountname"
        DETECTION_ACTIVE_DIRECTORY_DESCRIPTION: Final[str] = (
            "Active Directory attributes"
        )
        DETECTION_OID_ACL_DESCRIPTION: Final[str] = "Oracle OID ACLs"
        DETECTION_SCORE_SPECS: Final[
            tuple[tuple[FlextLdifConstantsEnums.ServerTypes, str, bool], ...]
        ] = (
            (FlextLdifConstantsEnums.ServerTypes.OID, DETECTION_OID_PATTERN_ATTR, True),
            (
                FlextLdifConstantsEnums.ServerTypes.OUD,
                DETECTION_OID_PATTERN_ATTR,
                False,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.OPENLDAP,
                DETECTION_PATTERN_ATTR,
                True,
            ),
            (FlextLdifConstantsEnums.ServerTypes.AD, DETECTION_PATTERN_ATTR, True),
            (FlextLdifConstantsEnums.ServerTypes.NOVELL, DETECTION_PATTERN_ATTR, False),
            (
                FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
                DETECTION_PATTERN_ATTR,
                False,
            ),
            (FlextLdifConstantsEnums.ServerTypes.DS389, DETECTION_PATTERN_ATTR, False),
            (FlextLdifConstantsEnums.ServerTypes.APACHE, DETECTION_PATTERN_ATTR, False),
        )
        DETECTION_PATTERN_SPECS: Final[
            tuple[tuple[FlextLdifConstantsEnums.ServerTypes, str, str, bool], ...]
        ] = (
            (
                FlextLdifConstantsEnums.ServerTypes.OID,
                DETECTION_OID_PATTERN_ATTR,
                "Oracle OID namespace (2.16.840.1.113894.*)",
                True,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.OUD,
                DETECTION_OID_PATTERN_ATTR,
                "Oracle OUD attributes (ds-sync-*)",
                False,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.OPENLDAP,
                DETECTION_PATTERN_ATTR,
                "OpenLDAP configuration (olc*)",
                True,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.AD,
                DETECTION_OID_PATTERN_ATTR,
                "Active Directory namespace (1.2.840.113556.*)",
                True,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.NOVELL,
                DETECTION_PATTERN_ATTR,
                "Novell eDirectory attributes (GUID, Modifiers, etc.)",
                False,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.DS389,
                DETECTION_PATTERN_ATTR,
                "389 Directory Server attributes (389ds, redhat-ds, dirsrv)",
                False,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.APACHE,
                DETECTION_PATTERN_ATTR,
                "Apache DS attributes (apacheDS, apache-*)",
                False,
            ),
            (
                FlextLdifConstantsEnums.ServerTypes.IBM_TIVOLI,
                DETECTION_PATTERN_ATTR,
                "IBM Tivoli attributes (ibm-*, tivoli, ldapdb)",
                False,
            ),
        )

        CLASS_SUFFIXES: Final[t.StrSequence] = ("Acl", "Schema", "Entry", "Constants")

        PROCESSING_STAGE_NORMALIZE_DN: Final[str] = "normalize_dn"
        PROCESSING_STAGE_NORMALIZE_ATTRS: Final[str] = "normalize_attrs"
        PROCESSING_STAGE_SERVER_TRANSFORM: Final[str] = "server_transform"
        ENTRY_OPERATION_REMOVE_ATTRIBUTES: Final[str] = "remove_attributes"

        CATEGORY_BUCKET_ORDER: Final[tuple[FlextLdifConstantsEnums.Category, ...]] = (
            FlextLdifConstantsEnums.Category.SCHEMA,
            FlextLdifConstantsEnums.Category.HIERARCHY,
            FlextLdifConstantsEnums.Category.USERS,
            FlextLdifConstantsEnums.Category.GROUPS,
            FlextLdifConstantsEnums.Category.ACL,
            FlextLdifConstantsEnums.Category.REJECTED,
        )
        CATEGORY_FILTERABLE_BY_BASE_DN: Final[
            frozenset[FlextLdifConstantsEnums.Category]
        ] = frozenset({
            FlextLdifConstantsEnums.Category.HIERARCHY,
            FlextLdifConstantsEnums.Category.USERS,
            FlextLdifConstantsEnums.Category.GROUPS,
            FlextLdifConstantsEnums.Category.ACL,
        })
        CATEGORY_VALUES: Final[frozenset[str]] = frozenset(
            category.value for category in FlextLdifConstantsEnums.Category
        )
        DEFAULT_CATEGORIZATION_PRIORITY: Final[
            tuple[FlextLdifConstantsEnums.Category, ...]
        ] = (
            FlextLdifConstantsEnums.Category.HIERARCHY,
            FlextLdifConstantsEnums.Category.USERS,
            FlextLdifConstantsEnums.Category.GROUPS,
            FlextLdifConstantsEnums.Category.ACL,
        )
        CATEGORY_RULE_OBJECTCLASS_FIELDS: Final[t.MappingKV[str, str]] = (
            MappingProxyType({
                FlextLdifConstantsEnums.Category.HIERARCHY: ("hierarchy_objectclasses"),
                FlextLdifConstantsEnums.Category.USERS: "user_objectclasses",
                FlextLdifConstantsEnums.Category.GROUPS: "group_objectclasses",
            })
        )
        CATEGORY_RULE_ATTRIBUTE_FIELDS: Final[t.MappingKV[str, str]] = (
            MappingProxyType({FlextLdifConstantsEnums.Category.ACL: "acl_attributes"})
        )
        CATEGORY_ATTRIBUTE_MARKER_PREFIX: Final[str] = "attr:"
        DN_PREVIEW_LENGTH: Final[int] = 100
        EMPTY_STR_FROZENSET: Final[frozenset[str]] = frozenset()

        MATCHING_RULES: Final[str] = "matchingRules"
        MATCHING_RULE_USE: Final[str] = "matchingRuleUse"
        LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"
        SCHEMA_OID_ATTRIBUTE_KEYS: Final[t.StrPairTuple] = (
            (FlextLdifConstantsBase.ATTRIBUTE_TYPES, "attributetypes"),
            (FlextLdifConstantsBase.OBJECT_CLASSES, "objectclasses"),
            (MATCHING_RULES, "matchingrules"),
            (MATCHING_RULE_USE, "matchingruleuse"),
            (LDAP_SYNTAXES, "ldapsyntaxes"),
        )
        SCHEMA_CATEGORY_ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
            key_pair[1] for key_pair in SCHEMA_OID_ATTRIBUTE_KEYS
        )
        OID_SCHEMA_DN: Final[str] = "cn=subschemasubentry"
        RFC_SCHEMA_DN: Final[str] = "cn=schema"
        SCHEMA_DN_MARKERS: Final[frozenset[str]] = frozenset({
            OID_SCHEMA_DN,
            "cn=subschema",
            RFC_SCHEMA_DN,
        })
        SCHEMA_OBJECTCLASS_MARKERS: Final[frozenset[str]] = frozenset({
            "subschema",
            "subentry",
        })
        WHITELIST_RULE_OID_FIELDS: Final[t.StrSequence] = (
            "allowed_attribute_oids",
            "allowed_objectclass_oids",
            "allowed_matchingrule_oids",
            "allowed_matchingruleuse_oids",
            "allowed_ldapsyntax_oids",
        )
        WHITELIST_RULE_SCHEMA_ATTRIBUTE_KEYS: Final[tuple[tuple[str, str], ...]] = (
            tuple(
                (field_name, attr_keys[1])
                for field_name, attr_keys in zip(
                    WHITELIST_RULE_OID_FIELDS, SCHEMA_OID_ATTRIBUTE_KEYS, strict=True
                )
            )
        )

        REJECTION_REASON_NO_CATEGORY_MATCH: Final[str] = "No category match"
        ERR_FAILED_NORMALIZE_RULES: Final[str] = "Failed to normalize rules"
        ERR_FAILED_FILTER_ENTRIES: Final[str] = "Failed to filter entries"
        ERR_SERVER_REGISTRY_UNAVAILABLE: Final[str] = "Server registry not available"
        ERR_UNKNOWN: Final[str] = "Unknown error"

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

        UNKNOWN_VALUE: Final[str] = "unknown"
        ASCII_THRESHOLD: Final[int] = 127

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
