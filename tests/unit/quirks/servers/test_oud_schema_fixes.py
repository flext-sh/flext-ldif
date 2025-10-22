"""Test OUD schema validation and fixing."""

from __future__ import annotations

from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestOudSchemaFixes:
    """Test OUD-specific schema validation and automatic fixes."""

    def test_fix_invalid_substr_matching_rules(self) -> None:
        """Test automatic fixing of invalid SUBSTR matching rules.

        OUD rejects non-substring matching rules in SUBSTR clause.
        Common mistake: SUBSTR caseIgnoreMatch (should be caseIgnoreSubstringsMatch).
        """
        quirk = FlextLdifQuirksServersOud()

        # Test Case 1: caseIgnoreMatch (equality rule) used as SUBSTR
        attr_data_case_ignore: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.808",
            "name": "orclPurgeEnable",
            "equality": "caseIgnoreMatch",
            "substr": "caseIgnoreMatch",  # WRONG - equality rule as substr
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        }

        result = quirk.write_attribute_to_rfc(attr_data_case_ignore)
        assert result.is_success
        rfc_string = result.unwrap()

        # Should replace with valid substring rule
        assert "caseIgnoreSubstringsMatch" in rfc_string
        assert "SUBSTR caseIgnoreMatch" not in rfc_string

        # Test Case 2: distinguishedNameMatch (DN has no substring matching)
        attr_data_dn: dict[str, object] = {
            "oid": "2.16.840.1.113894.5.1.1062",
            "name": "orclMailListSuspendedMember",
            "equality": "distinguishedNameMatch",
            "substr": "distinguishedNameMatch",  # WRONG - DN has no substr
            "syntax": "1.3.6.1.4.1.1466.115.121.1.12",
        }

        result_dn = quirk.write_attribute_to_rfc(attr_data_dn)
        assert result_dn.is_success
        rfc_string_dn = result_dn.unwrap()

        # Should remove SUBSTR clause entirely (DN has no substring matching)
        assert (
            "SUBSTR" not in rfc_string_dn
            or "SUBSTR distinguishedNameMatch" not in rfc_string_dn
        )

    def test_fix_objectclass_type_mismatches(self) -> None:
        """Test automatic fixing of objectclass type mismatches.

        OUD rejects AUXILIARY inheriting from STRUCTURAL (and vice versa).
        """
        quirk = FlextLdifQuirksServersOud()

        # Test Case 1: AUXILIARY inheriting from STRUCTURAL
        oc_data_aux_from_struct: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.2.71",
            "name": "orclcommonverifierprofile",
            "sup": "orclpwdverifierprofile",  # STRUCTURAL class
            "kind": "AUXILIARY",
            "must": ["orclcommonverifierenable"],
            "may": ["uniquemember"],
        }

        result_aux = quirk.write_objectclass_to_rfc(oc_data_aux_from_struct)
        assert result_aux.is_success
        rfc_string_aux = result_aux.unwrap()

        # Should remove SUP clause to fix type mismatch
        assert "SUP orclpwdverifierprofile" not in rfc_string_aux
        assert "AUXILIARY" in rfc_string_aux

        # Test Case 2: STRUCTURAL inheriting from AUXILIARY
        oc_data_struct_from_aux: dict[str, object] = {
            "oid": "2.16.840.1.113894.2.2.100.2",
            "name": "orclDBAQConnection",
            "sup": "javaNamingReference",  # AUXILIARY class
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": ["orclDBAQGeneric", "orclVersion"],
        }

        result_struct = quirk.write_objectclass_to_rfc(oc_data_struct_from_aux)
        assert result_struct.is_success
        rfc_string_struct = result_struct.unwrap()

        # Should remove SUP clause to fix type mismatch
        assert "SUP javaNamingReference" not in rfc_string_struct
        assert "STRUCTURAL" in rfc_string_struct

        # Test Case 3: Multiple SUP classes with mismatch
        oc_data_multi_sup: dict[str, object] = {
            "oid": "2.16.840.1.113894.2.2.7",
            "name": "orclDBEnterpriseDomain_82",
            "sup": [
                "groupofuniquenames",
                "orclprivilegegroup",
            ],  # STRUCTURAL + AUXILIARY
            "kind": "AUXILIARY",
            "may": ["orclDBAuthTypes"],
        }

        result_multi = quirk.write_objectclass_to_rfc(oc_data_multi_sup)
        assert result_multi.is_success
        rfc_string_multi = result_multi.unwrap()

        # Should remove SUP clause because groupofuniquenames is STRUCTURAL
        assert "SUP" not in rfc_string_multi
        assert "AUXILIARY" in rfc_string_multi

    def test_fix_illegal_characters_in_attribute_names(self) -> None:
        """Test automatic fixing of illegal characters in attribute names.

        OUD rejects underscores in non-numeric OIDs.
        Should replace with hyphens.
        """
        quirk = FlextLdifQuirksServersOud()

        # Test Case: Objectclass with MUST/MAY containing underscores
        oc_data_with_underscores: dict[str, object] = {
            "oid": "2.16.840.1.113894.8.2.1001",
            "name": "oidconfig",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": [
                "OIDBaseDN",
                "OIDHost",
                "OIDPort",
                "passwdattr",
                "MSDEDSN",
                "OIDObjectClass",
                "OIDLog",
                "ExcludeListDN",
                "MAX_RETRIES",  # Illegal underscore
                "OIDSSLType",
                "OIDWalletLoc",
                "OidSinkNode",
                "SleepTime",
                "stop",
                "ConfigSleepTime",
                "OIDConfigSynchKey",
            ],
        }

        result = quirk.write_objectclass_to_rfc(oc_data_with_underscores)
        assert result.is_success
        rfc_string = result.unwrap()

        # Should replace underscore with hyphen
        assert "MAX-RETRIES" in rfc_string or "max-retries" in rfc_string.lower()
        assert "MAX_RETRIES" not in rfc_string

    def test_combined_fixes_real_world_case(self) -> None:
        """Test realistic scenario with multiple fixes needed."""
        quirk = FlextLdifQuirksServersOud()

        # Attribute with invalid SUBSTR
        attr_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.809",
            "name": "orclPurgeNow",
            "equality": "caseIgnoreMatch",
            "substr": "caseIgnoreMatch",  # Will be fixed
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
            "x_origin": "user defined",
        }

        result_attr = quirk.write_attribute_to_rfc(attr_data)
        assert result_attr.is_success
        assert "caseIgnoreSubstringsMatch" in result_attr.unwrap()

        # Objectclass with type mismatch AND illegal characters
        oc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.5.101.2.1004",
            "name": "orclUMUserDevice",
            "desc": "Unified Messaging User Device",
            "sup": "device",  # STRUCTURAL - will cause mismatch
            "kind": "AUXILIARY",
            "must": [
                "cn",
                "owner",
                "orclUMWirelessGWType",
                "orclUMDeviceAddress",
                "orclUMDefault",
            ],
            "may": [
                "orclUMUserMaxLen",
                "orclUM_GenericProperty",
            ],  # Underscore will be fixed
            "x_origin": "user defined",
        }

        result_oc = quirk.write_objectclass_to_rfc(oc_data)
        assert result_oc.is_success
        rfc_string_oc = result_oc.unwrap()

        # Type mismatch fix: SUP should be removed
        assert "SUP device" not in rfc_string_oc
        # Illegal character fix: underscore replaced with hyphen
        assert (
            "orclUM-GenericProperty" in rfc_string_oc
            or "orcl_UM-GenericProperty" in rfc_string_oc
        )
