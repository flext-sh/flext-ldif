"""Oracle ACL Examples from Official Documentation.

Examples extracted from:
- Oracle OID ACL Documentation
- Oracle OUD ACI Syntax Documentation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


class OracleOidAclExamples:
    """OID ACL examples from Oracle documentation."""

    # Example 1: BINDMODE - Authentication/encryption requirements
    BINDMODE_SIMPLE = """dn: cn=testuser,dc=example,dc=com
orclaci: access to entry by * (browse,read) bindmode=(Simple)
objectClass: person
cn: testuser
sn: User
"""

    BINDMODE_SSL = """dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
orclaci: access to entry by * (browse,read,write) bindmode=(SSLOneway)
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD
sn: Administrator
"""

    # Example 2: DenyGroupOverride - Prevents override by higher ACPs
    DENY_GROUP_OVERRIDE = """dn: cn=protected,dc=example,dc=com
orclaci: access to entry by group=cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com (all) DenyGroupOverride
objectClass: person
cn: protected
sn: Protected
"""

    # Example 3: AppendToAll - Adds subject to all other ACIs
    APPEND_TO_ALL = """dn: cn=global,dc=example,dc=com
orclaci: access to entry by * (browse) AppendToAll
objectClass: person
cn: global
sn: Global
"""

    # Example 4: BINDIPFILTER - IP-based access restriction
    BIND_IP_FILTER = """dn: cn=restricted,dc=example,dc=com
orclaci: access to entry by * (browse,read) bindipfilter=(orclipaddress=192.168.1.*)
objectClass: person
cn: restricted
sn: Restricted
"""

    # Example 5: constraintonaddedobject - Entry type constraints
    CONSTRAIN_TO_ADDED_OBJECT = """dn: ou=users,dc=example,dc=com
orclaci: access to entry by group=cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com (add) constraintonaddedobject=(objectclass=person)
objectClass: organizationalUnit
ou: users
"""

    # Example 6: Combined features
    ALL_FEATURES_COMBINED = """dn: cn=secure,dc=example,dc=com
orclaci: access to entry by group=cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com (browse,read,write) bindmode=(SSLOneway) DenyGroupOverride AppendToAll bindipfilter=(orclipaddress=10.0.0.*) constraintonaddedobject=(objectclass=inetOrgPerson)
objectClass: person
cn: secure
sn: Secure
"""

    # Example 7: Multiple ACLs on same entry
    MULTIPLE_ACLS = """dn: cn=multi,dc=example,dc=com
orclaci: access to entry by * (browse) bindmode=(Anonymous)
orclaci: access to attr=(cn,sn) by SELF (read,write)
orclaci: access to attr=(userPassword) by group=cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com (all) DenyGroupOverride
objectClass: person
cn: multi
sn: Multiple
"""


class OracleOudAciExamples:
    """OUD ACI examples from Oracle documentation."""

    # Example 1: targattrfilters - Attribute value filtering
    TARGATTRFILTERS = """dn: cn=testuser,dc=example,dc=com
aci: (targetattr="cn")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")(version 3.0; acl "Filter CN additions"; allow (add) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
objectClass: person
cn: testuser
sn: User
"""

    # Example 2: targetcontrol - LDAP control OID targeting
    TARGETCONTROL = """dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
aci: (targetattr="*")(targetcontrol="1.3.6.1.4.1.42.2.27.9.5.2")(version 3.0; acl "Proxy Auth Control"; allow (read,search) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD
sn: Administrator
"""

    # Example 3: extop - Extended operation OID
    EXTOP = """dn: cn=pwdREDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
aci: (targetattr="*")(extop="1.3.6.1.4.1.26027.1.6.1")(version 3.0; acl "Password Modify ExtOp"; allow (read) userdn="ldap:///uid=pwdREDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
objectClass: person
cn: pwdREDACTED_LDAP_BIND_PASSWORD
sn: Password Administrator
"""

    # Example 4: ip bind rule - IP/CIDR filtering
    BIND_IP = """dn: cn=restricted,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "IP restricted access"; allow (read,search) userdn="ldap:///self" and ip="192.168.1.0/24";)
objectClass: person
cn: restricted
sn: Restricted
"""

    # Example 5: dns bind rule - DNS pattern matching
    BIND_DNS = """dn: cn=internal,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "DNS restricted access"; allow (read,search) userdn="ldap:///self" and dns="*.internal.example.com";)
objectClass: person
cn: internal
sn: Internal
"""

    # Example 6: dayofweek bind rule - Day restrictions
    BIND_DAYOFWEEK = """dn: cn=weekday,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Weekday only access"; allow (read,search) userdn="ldap:///self" and dayofweek="Mon,Tue,Wed,Thu,Fri";)
objectClass: person
cn: weekday
sn: Weekday
"""

    # Example 7: timeofday bind rule - Time restrictions
    BIND_TIMEOFDAY = """dn: cn=business,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Business hours only"; allow (read,search) userdn="ldap:///self" and timeofday >= "0800" and timeofday <= "1800";)
objectClass: person
cn: business
sn: Business
"""

    # Example 8: authmethod bind rule - Required auth method
    BIND_AUTHMETHOD = """dn: cn=secure,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "SSL required"; allow (read,search) userdn="ldap:///self" and authmethod = "ssl";)
objectClass: person
cn: secure
sn: Secure
"""

    # Example 9: ssf bind rule - Security Strength Factor
    BIND_SSF = """dn: cn=encrypted,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "High encryption required"; allow (read,search) userdn="ldap:///self" and ssf >= "128";)
objectClass: person
cn: encrypted
sn: Encrypted
"""

    # Example 10: Combined target extensions
    TARGET_EXTENSIONS_COMBINED = """dn: cn=controlled,dc=example,dc=com
aci: (targetattr="cn,sn")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")(targetcontrol="1.3.6.1.4.1.42.2.27.9.5.2")(extop="1.3.6.1.4.1.26027.1.6.1")(version 3.0; acl "Combined target extensions"; allow (add,read) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
objectClass: person
cn: controlled
sn: Controlled
"""

    # Example 11: Combined bind rules
    BIND_RULES_COMBINED = """dn: cn=restricted,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Multiple bind restrictions"; allow (read,search) userdn="ldap:///self" and ip="192.168.1.0/24" and dns="*.example.com" and dayofweek="Mon,Tue,Wed,Thu,Fri" and timeofday >= "0800" and timeofday <= "1800" and authmethod = "ssl" and ssf >= "128";)
objectClass: person
cn: restricted
sn: Restricted
"""

    # Example 12: All OUD features combined
    ALL_FEATURES_COMBINED = """dn: cn=maximum,dc=example,dc=com
aci: (targetattr="cn,sn,mail")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")(targetcontrol="1.3.6.1.4.1.42.2.27.9.5.2")(extop="1.3.6.1.4.1.26027.1.6.1")(version 3.0; acl "Maximum security ACL"; allow (add,read,search) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" and ip="10.0.0.0/8" and dns="*.secure.example.com" and dayofweek="Mon,Tue,Wed,Thu,Fri" and timeofday >= "0800" and timeofday <= "1800" and authmethod = "ssl" and ssf >= "256";)
objectClass: person
cn: maximum
sn: Maximum
mail: maximum@example.com
"""

    # Example 13: Multiple ACIs on same entry
    MULTIPLE_ACIS = """dn: cn=multi,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Anonymous read"; allow (read,search) userdn="ldap:///anyone";)
aci: (targetattr="userPassword")(version 3.0; acl "Self password change"; allow (write) userdn="ldap:///self";)
aci: (targetattr="*")(version 3.0; acl "Admin full access"; allow (all) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" and ip="10.0.0.1";)
objectClass: person
cn: multi
sn: Multiple
"""


class OracleAclConversionExamples:
    """Examples for OID ↔ OUD conversion testing."""

    # OID entry with features that have OUD equivalents
    OID_WITH_OUD_EQUIVALENTS = """dn: cn=convertible,dc=example,dc=com
orclaci: access to entry by * (browse,read) bindipfilter=(orclipaddress=192.168.1.*)
objectClass: person
cn: convertible
sn: Convertible
"""

    # Expected OUD conversion (BINDIPFILTER → ip bind rule)
    OUD_FROM_OID_CONVERSION = """dn: cn=convertible,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Converted from OID"; allow (read,search) userdn="ldap:///anyone" and ip="192.168.1.*";)
objectClass: person
cn: convertible
sn: Convertible
"""

    # OID entry with features that have NO OUD equivalents
    OID_WITHOUT_OUD_EQUIVALENTS = """dn: cn=oid-only,dc=example,dc=com
orclaci: access to entry by * (browse) DenyGroupOverride AppendToAll
objectClass: person
cn: oid-only
sn: OID Only
"""

    # Expected OUD conversion (DenyGroupOverride and AppendToAll preserved in metadata, not in ACI syntax)
    OUD_FROM_OID_METADATA_ONLY = """dn: cn=oid-only,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "Converted from OID"; allow (read,search) userdn="ldap:///anyone";)
objectClass: person
cn: oid-only
sn: OID Only
"""

    # OUD entry with features that have OID equivalents
    OUD_WITH_OID_EQUIVALENTS = """dn: cn=convertible-oud,dc=example,dc=com
aci: (targetattr="*")(version 3.0; acl "IP restricted"; allow (read,search) userdn="ldap:///self" and ip="10.0.0.0/8";)
objectClass: person
cn: convertible-oud
sn: Convertible OUD
"""

    # Expected OID conversion (ip bind rule → BINDIPFILTER)
    OID_FROM_OUD_CONVERSION = """dn: cn=convertible-oud,dc=example,dc=com
orclaci: access to entry by SELF (browse,read) bindipfilter=(orclipaddress=10.0.0.0/8)
objectClass: person
cn: convertible-oud
sn: Convertible OUD
"""

    # OUD entry with features that have NO OID equivalents
    OUD_WITHOUT_OID_EQUIVALENTS = """dn: cn=oud-only,dc=example,dc=com
aci: (targetattr="*")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")(extop="1.3.6.1.4.1.26027.1.6.1")(version 3.0; acl "OUD specific"; allow (add,read) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
objectClass: person
cn: oud-only
sn: OUD Only
"""

    # Expected OID conversion (targattrfilters and extop preserved in metadata, not in orclaci syntax)
    OID_FROM_OUD_METADATA_ONLY = """dn: cn=oud-only,dc=example,dc=com
orclaci: access to entry by dn=uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com (browse,read,add)
objectClass: person
cn: oud-only
sn: OUD Only
"""
