"""Service for manipulating LDAP entries with FlextLdifModels.

This service provides a centralized place for all operations related to
extracting, normalizing, and validating data within FlextLdifModels.Entry
objects. It encapsulates common patterns used across various domain services
to ensure consistency and reduce code duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import re

from flext_core import FlextResult, FlextRuntime
from ldap3 import Connection

# Use local constants - no dependency on flext_ldap
# LDAP3 exceptions - use generic Exception if not available
try:
    from ldap3 import LDAPAttributeError, LDAPObjectClassError
except ImportError:
    # ldap3 may not have these specific exceptions - use generic Exception
    LDAPAttributeError = Exception  # type: ignore[assignment, misc]
    LDAPObjectClassError = Exception  # type: ignore[assignment, misc]

from flext_ldif import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation


# Local constants for entry manipulation (fallback if FlextLdapConstants not available)
class _EntryManipulationConstants:
    """Local constants for entry manipulation operations."""

    class LockAttributes:
        """Lock attribute names for user account locking."""

        ALL_LOCK_ATTRIBUTES: list[str] = [
            "pwdAccountLockedTime",
            "accountLocked",
            "lockoutTime",
            "userAccountControl",
        ]

    class BooleanStrings:
        """Boolean string values for attribute normalization."""

        TRUE: str = "true"
        ONE: str = "1"
        YES: str = "yes"
        FALSE: str = "false"
        ZERO: str = "0"
        NO: str = "no"

    class UserStatus:
        """User account status values."""

        ACTIVE: str = "ACTIVE"
        LOCKED: str = "LOCKED"
        DISABLED: str = "DISABLED"

    class ActiveDirectoryFlags:
        """Active Directory user account control flags."""

        ADS_UF_ACCOUNTDISABLE: int = 0x0002

    class ActiveDirectoryAttributes:
        """Active Directory attribute names."""

        PWD_LAST_SET: str = "pwdLastSet"

    class RegexPatterns:
        """Regex patterns for entry manipulation."""

        USERNAME_SANITIZE_PATTERN: str = r"[^a-zA-Z0-9._-]"

    class LdapAttributeNames:
        """LDAP attribute names."""

        OBJECT_CLASS: str = "objectClass"

    class Defaults:
        """Default values for entry manipulation."""

        OBJECT_CLASS_TOP: str = "top"

    class Types:
        """Type definitions for entry manipulation."""

        class QuirksMode:
            """Quirks mode for LDAP operations."""

            RFC: str = "rfc"
            AUTOMATIC: str = "automatic"


class EntryManipulationServices:
    """Provides methods for manipulating FlextLdifModels.Entry objects.

    This service centralizes helper methods that extract, normalize, and validate
    data within LDAP entries. It is designed to be used by domain services to
    ensure consistent handling of entry data according to FlextLdifModels
    structure and domain-specific quirks.
    """

    _validation_service = FlextLdifValidation()

    @staticmethod
    def get_entry_attribute(
        entry: FlextLdifModels.Entry,
        attr_name: str,
    ) -> FlextResult[object]:
        """Safely get attribute value from LDAP entry.

        Args:
            entry: LDAP entry to extract attribute from.
            attr_name: Name of the attribute to retrieve.

        Returns:
            FlextResult with attribute value or failure if not found.

        """
        if not entry.attributes or not hasattr(entry.attributes, "attributes"):
            return FlextResult[object].fail(
                f"Entry has no attributes dictionary for attribute '{attr_name}'"
            )
        attr_dict = entry.attributes.attributes
        if not isinstance(attr_dict, dict):
            return FlextResult[object].fail(
                f"Entry attributes is not a dictionary for attribute '{attr_name}'"
            )
        if attr_name not in attr_dict:
            return FlextResult[object].fail(
                f"Attribute '{attr_name}' not found in entry"
            )
        return FlextResult[object].ok(attr_dict[attr_name])

    @staticmethod
    def normalize_attribute_value(attr_value: object | None) -> FlextResult[str]:
        """Normalize LDAP attribute value to string.

        Args:
            attr_value: Raw LDAP attribute value (list or single value).

        Returns:
            FlextResult with normalized string value or failure if invalid/empty.

        """
        if attr_value is None:
            return FlextResult[str].fail("Attribute value is None")

        if FlextRuntime.is_list_like(attr_value) and len(attr_value) > 0:
            return FlextResult[str].ok(str(attr_value[0]))

        try:
            str_value = str(attr_value).strip()
            if not str_value:
                return FlextResult[str].fail(
                    "Attribute value is empty after normalization"
                )
            return FlextResult[str].ok(str_value)
        except (TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to normalize attribute value: {e}")

    @staticmethod
    def get_normalized_attribute(
        entry: FlextLdifModels.Entry,
        attr_name: str,
    ) -> FlextResult[str]:
        """Get and normalize LDAP attribute value.

        Args:
            entry: LDAP entry to extract attribute from.
            attr_name: Name of the attribute to retrieve and normalize.

        Returns:
            FlextResult with normalized string value or failure if not found/invalid.

        """
        raw_value_result = EntryManipulationServices.get_entry_attribute(
            entry, attr_name
        )
        if not raw_value_result.is_success:
            return FlextResult[str].fail(
                f"Failed to get attribute '{attr_name}': {raw_value_result.error}"
            )
        return EntryManipulationServices.normalize_attribute_value(
            raw_value_result.unwrap()
        )

    @staticmethod
    def build_display_name_from_parts(
        given_name: str | None,
        sn: str | None,
    ) -> FlextResult[str]:
        """Build display name from given name and surname parts.

        Args:
            given_name: User's given/first name.
            sn: User's surname/last name.

        Returns:
            FlextResult with formatted full name or failure if insufficient parts.

        """
        if not given_name or not sn:
            return FlextResult[str].fail(
                "Insufficient name parts: both given_name and sn are required"
            )
        return FlextResult[str].ok(f"{given_name} {sn}")

    def get_display_name_priority_list(
        self,
        user: FlextLdifModels.Entry,
    ) -> list[FlextResult[str]]:
        """Get prioritized list of display name candidates.

        Args:
            user: LDAP user entry.

        Returns:
            Ordered list of FlextResult[str] for display name candidates (first success wins).

        """
        given_name_result = self.get_normalized_attribute(user, "givenName")
        sn_result = self.get_normalized_attribute(user, "sn")

        # Build display name from parts if both are available
        if given_name_result.is_success and sn_result.is_success:
            display_name_result = self.build_display_name_from_parts(
                given_name_result.unwrap(), sn_result.unwrap()
            )
        else:
            display_name_result = FlextResult[str].fail("Insufficient name parts")

        return [
            self.get_normalized_attribute(user, "displayName"),
            display_name_result,
            self.get_normalized_attribute(user, "cn"),
            self.get_normalized_attribute(user, "uid"),
        ]

    def calculate_user_display_name(self, user: FlextLdifModels.Entry) -> str:
        """Calculate display name for user based on domain rules.

        Args:
            user: LDAP user entry.

        Returns:
            Formatted display name for user or UNKNOWN_USER fallback.

        """
        display_options = self.get_display_name_priority_list(user)

        for option_result in display_options:
            if option_result.is_success:
                return option_result.unwrap()

        return "UNKNOWN_USER"

    def check_lock_attributes(self, user: FlextLdifModels.Entry) -> FlextResult[str]:
        """Check user lock attributes.

        Args:
            user: LDAP user entry to check.

        Returns:
            FlextResult with status string if locked/disabled, or success with ACTIVE if active.

        """
        # Use local constants (FlextLdapConstants may not be available)
        try:
            from flext_ldap.constants import (
                FlextLdapConstants,  # type: ignore[import-untyped]
            )

            constants = FlextLdapConstants
        except (ImportError, ModuleNotFoundError):
            constants = _EntryManipulationConstants

        lock_attrs_attr = getattr(
            constants, "LockAttributes", _EntryManipulationConstants.LockAttributes
        )
        lock_attrs = getattr(
            lock_attrs_attr,
            "ALL_LOCK_ATTRIBUTES",
            _EntryManipulationConstants.LockAttributes.ALL_LOCK_ATTRIBUTES,
        )

        for attr in lock_attrs:
            attr_value_result = self.get_entry_attribute(user, attr)
            if not attr_value_result.is_success:
                continue

            normalized_result = self.normalize_attribute_value(
                attr_value_result.unwrap()
            )
            if normalized_result.is_failure:
                continue

            normalized_value = normalized_result.unwrap()
            boolean_strings = getattr(
                constants, "BooleanStrings", _EntryManipulationConstants.BooleanStrings
            )
            true_val = getattr(
                boolean_strings, "TRUE", _EntryManipulationConstants.BooleanStrings.TRUE
            )
            one_val = getattr(
                boolean_strings, "ONE", _EntryManipulationConstants.BooleanStrings.ONE
            )
            yes_val = getattr(
                boolean_strings, "YES", _EntryManipulationConstants.BooleanStrings.YES
            )
            if normalized_value.lower() in {
                str(true_val).lower(),
                str(one_val),
                str(yes_val).lower(),
            }:
                user_status = getattr(
                    constants, "UserStatus", _EntryManipulationConstants.UserStatus
                )
                locked_status = getattr(
                    user_status, "LOCKED", _EntryManipulationConstants.UserStatus.LOCKED
                )
                return FlextResult[str].ok(locked_status)

            try:
                ad_flags = getattr(
                    constants,
                    "ActiveDirectoryFlags",
                    _EntryManipulationConstants.ActiveDirectoryFlags,
                )
                ads_uf_accountdisable = getattr(
                    ad_flags,
                    "ADS_UF_ACCOUNTDISABLE",
                    _EntryManipulationConstants.ActiveDirectoryFlags.ADS_UF_ACCOUNTDISABLE,
                )
                if int(normalized_value) & ads_uf_accountdisable:
                    user_status = getattr(
                        constants, "UserStatus", _EntryManipulationConstants.UserStatus
                    )
                    disabled_status = getattr(
                        user_status,
                        "DISABLED",
                        _EntryManipulationConstants.UserStatus.DISABLED,
                    )
                    return FlextResult[str].ok(disabled_status)
            except (ValueError, TypeError):
                continue

        user_status = getattr(
            constants, "UserStatus", _EntryManipulationConstants.UserStatus
        )
        active_status = getattr(
            user_status, "ACTIVE", _EntryManipulationConstants.UserStatus.ACTIVE
        )
        return FlextResult[str].ok(active_status)

    def check_password_expiry(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user password is expired.

        Args:
            user: LDAP user entry to check.

        Returns:
            True if password is considered expired (simplified check).

        """
        pwd_last_set_result = self.get_entry_attribute(
            user,
            _EntryManipulationConstants.ActiveDirectoryAttributes.PWD_LAST_SET,
        )
        return pwd_last_set_result.is_success

    def determine_user_status(self, user: FlextLdifModels.Entry) -> str:
        """Determine user status based on LDAP attributes.

        Args:
            user: LDAP user entry.

        Returns:
            User status string ("active", "locked", "disabled").

        """
        lock_status_result = self.check_lock_attributes(user)
        if lock_status_result.is_success:
            status = lock_status_result.unwrap()
            # If status is not ACTIVE, return it (LOCKED or DISABLED)
            if status != _EntryManipulationConstants.UserStatus.ACTIVE:
                return status

        if self.check_password_expiry(user):
            return _EntryManipulationConstants.UserStatus.ACTIVE

        return _EntryManipulationConstants.UserStatus.ACTIVE

    def check_group_email_requirement(
        self,
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Check if group requires email membership.

        Args:
            user: LDAP user entry.
            group: LDAP group entry.

        Returns:
            FlextResult[bool]: Success if requirement met, failure with error message if not.

        """
        group_cn_result = self.get_normalized_attribute(group, "cn")
        user_email_result = self.get_normalized_attribute(user, "mail")

        if not group_cn_result.is_success:
            return FlextResult[bool].ok(True)  # No group CN, no requirement

        group_cn = group_cn_result.unwrap()
        user_email = (
            user_email_result.unwrap() if user_email_result.is_success else None
        )

        if "admin" in group_cn.lower() and not user_email:
            return FlextResult[bool].fail(
                "Admin group members must have email addresses"
            )

        return FlextResult[bool].ok(True)

    def check_user_active_status(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user is active (not locked).

        Args:
            user: LDAP user entry.

        Returns:
            True if user is active, False if locked.

        """
        lock_status_result = self.check_lock_attributes(user)
        if not lock_status_result.is_success:
            return False
        status = lock_status_result.unwrap()
        return status == _EntryManipulationConstants.UserStatus.ACTIVE

    def validate_group_membership_rules(
        self,
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Validate if user can be member of group based on business rules.

        Args:
            user: LDAP user entry.
            group: LDAP group entry.

        Returns:
            FlextResult indicating if membership is valid.

        """
        email_check_result = self.check_group_email_requirement(user, group)
        if not email_check_result.is_success:
            return email_check_result

        if not self.check_user_active_status(user):
            return FlextResult[bool].fail("Inactive users cannot be added to groups")

        return FlextResult[bool].ok(True)

    def normalize_username_base(
        self,
        base_name: str,
        validation_service: FlextLdifValidation,
    ) -> FlextResult[str]:
        """Normalize username base using domain rules and validation.

        Args:
            base_name: Raw base name to normalize.

        Returns:
            FlextResult with normalized username or validation error.

        """
        if not base_name:
            return FlextResult[str].fail("Base name cannot be empty")

        username = base_name.lower().replace(" ", "_")

        username = re.sub(
            _EntryManipulationConstants.RegexPatterns.USERNAME_SANITIZE_PATTERN,
            "",
            username,
        )

        if not username:
            return FlextResult[str].fail("Base name contains no valid characters")

        validation_result = validation_service.validate_attribute_name(username)
        if validation_result.is_failure or not validation_result.unwrap():
            return FlextResult[str].fail(
                f"Generated username '{username}' does not meet LDAP attribute name requirements",
            )

        return FlextResult[str].ok(username)

    def collect_existing_uids(
        self,
        existing_users: list[FlextLdifModels.Entry],
    ) -> set[str]:
        """Collect existing UIDs from user entries.

        Args:
            existing_users: List of existing LDAP user entries.

        Returns:
            Set of normalized existing UIDs.

        """
        existing_uids = set()
        for user in existing_users:
            uid_result = self.get_normalized_attribute(user, "uid")
            if uid_result.is_success:
                existing_uids.add(uid_result.unwrap())
        return existing_uids

    def generate_username_with_suffix(
        self,
        base_username: str,
        existing_uids: set[str],
        max_attempts: int,
    ) -> FlextResult[str]:
        """Generate unique username with numeric suffix.

        Args:
            base_username: Base username to extend.
            existing_uids: Set of existing usernames to avoid.
            max_attempts: Maximum suffix attempts.

        Returns:
            FlextResult with unique username or failure.

        """
        if base_username not in existing_uids:
            return FlextResult[str].ok(base_username)

        for i in range(1, max_attempts):
            candidate = f"{base_username}{i}"
            if candidate not in existing_uids:
                return FlextResult[str].ok(candidate)

        return FlextResult[str].fail(
            f"Could not generate unique username after {max_attempts} attempts",
        )

    def generate_unique_username(
        self,
        base_name: str,
        existing_users: list[FlextLdifModels.Entry],
        max_attempts: int = 100,
        validation_service: FlextLdifValidation | None = None,
    ) -> FlextResult[str]:
        """Generate unique username based on domain rules.

        Args:
            base_name: Base name to derive username from.
            existing_users: List of existing LDAP user entries.
            max_attempts: Maximum attempts to generate unique name.

        Returns:
            FlextResult with generated unique username or error.

        """
        normalized_result = self.normalize_username_base(
            base_name,
            validation_service or self._validation_service,
        )
        if normalized_result.is_failure:
            return normalized_result

        base_username = normalized_result.unwrap()

        existing_uids = self.collect_existing_uids(existing_users)

        return self.generate_username_with_suffix(
            base_username,
            existing_uids,
            max_attempts,
        )

    @staticmethod
    def convert_ldif_attributes_to_ldap3_format(
        attributes: FlextLdifModels.LdifAttributes | dict[str, str | list[str]],
    ) -> dict[str, list[str]]:
        """Convert attributes to ldap3 format (dict with list values)."""
        attrs_dict: dict[str, str | list[str]]
        if isinstance(attributes, FlextLdifModels.LdifAttributes):
            attrs_dict = (
                attributes  # attributes.attributes is already dict[str, list[str]]
            )
        else:
            attrs_dict = attributes

        ldap3_attributes: dict[str, list[str]] = {}
        for key, value in attrs_dict.items():
            if FlextRuntime.is_list_like(value):
                # Convert list-like object to list of strings
                # Iterate over the value if it's a list-like type (e.g., tuple, set, etc.)
                # and convert each item to string, then wrap in a list.
                # This handles cases where value is list, tuple, set, etc.
                ldap3_attributes[key] = [str(item) for item in value]
            else:
                ldap3_attributes[key] = [str(value)]
        return ldap3_attributes

    def add_entry(
        self,
        connection: Connection,
        dn: FlextLdifModels.DistinguishedName | str,
        attributes: FlextLdifModels.LdifAttributes | dict[str, str | list[str]],
        quirks_mode: str | None = None,
        logger: logging.Logger | None = None,
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Handles undefined attributes gracefully by filtering them out and retrying.
        This makes the API extensible to work with any LDAP schema without limitations.

        Args:
            connection: The active ldap3 connection.
            dn: Distinguished name for new entry.
            attributes: Entry attributes (FlextLdifModels.LdifAttributes or dict).
            quirks_mode: Override default quirks mode for this operation.
            logger: Optional logger instance for logging.

        Returns:
            FlextResult[bool]: Success if entry was added.

        """
        if logger is None:
            logger = logging.getLogger(__name__)

        try:
            # Determine effective quirks mode
            try:
                from flext_ldap.constants import (
                    FlextLdapConstants,  # type: ignore[import-untyped]
                )

                default_mode = FlextLdapConstants.Types.QuirksMode.AUTOMATIC
                rfc_mode = FlextLdapConstants.Types.QuirksMode.RFC
            except (ImportError, ModuleNotFoundError):
                default_mode = _EntryManipulationConstants.Types.QuirksMode.AUTOMATIC
                rfc_mode = _EntryManipulationConstants.Types.QuirksMode.RFC

            effectives_mode = (
                quirks_mode or default_mode
            )  # Default to AUTOMATIC if not provided

            # Convert attributes to ldap3 format
            ldap3_attributes = self.convert_ldif_attributes_to_ldap3_format(attributes)

            # Convert DN to string
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )

            # Retry logic with undefined attribute handling
            attempted_attributes = ldap3_attributes.copy()
            removed_attributes: list[str] = []
            max_retries = 1 if effectives_mode == rfc_mode else 20
            retry_count = 0

            logger.debug(
                "Adding entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            while retry_count < max_retries:
                try:
                    success = self._attempt_add_entry_internal(
                        connection,
                        dn_str,
                        attempted_attributes,
                    )
                    if success:
                        if removed_attributes:
                            logger.debug("Removed attrs: %s", removed_attributes)
                        return FlextResult[bool].ok(True)

                    # Try to handle undefined attribute error
                    if self._handle_undefined_attribute_error_internal(
                        connection,
                        attempted_attributes,
                        removed_attributes,
                        logger,
                    ):
                        retry_count += 1
                        continue

                    # Unknown error
                    return FlextResult[bool].fail(
                        f"Add entry failed: {connection.last_error}",
                    )

                except Exception as e:
                    error_str = str(e).lower()
                    if (
                        "undefined attribute" in error_str
                        or "invalid attribute" in error_str
                    ):
                        problem_attr_result = (
                            self._extract_undefined_attribute_internal(
                                str(e),
                                attempted_attributes,
                            )
                        )
                        if problem_attr_result.is_success:
                            problem_attr = problem_attr_result.unwrap()
                            logger.debug("Exception on undefined '%s'", problem_attr)
                            del attempted_attributes[problem_attr]
                            removed_attributes.append(problem_attr)
                            retry_count += 1
                            continue
                    raise

            # Exhausted retries
            return FlextResult[bool].fail(
                f"Add entry failed after {max_retries} retries removing attributes",
            )

        except Exception as e:
            logger.exception("Add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    def _attempt_add_entry_internal(
        self,
        connection: Connection,
        dn_str: str,
        attempted_attributes: dict[str, list[str]],
    ) -> bool:
        """Attempt to add entry with current attributes (internal helper)."""
        try:
            from flext_ldap.constants import (
                FlextLdapConstants,  # type: ignore[import-untyped]
            )

            object_class_attr = FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            default_object_class = FlextLdapConstants.Defaults.OBJECT_CLASS_TOP
        except (ImportError, ModuleNotFoundError):
            object_class_attr = (
                _EntryManipulationConstants.LdapAttributeNames.OBJECT_CLASS
            )
            default_object_class = _EntryManipulationConstants.Defaults.OBJECT_CLASS_TOP

        object_class_raw = attempted_attributes.get(
            object_class_attr,
            [default_object_class],
        )
        if FlextRuntime.is_list_like(object_class_raw):
            object_class = (
                str(object_class_raw[0]) if object_class_raw else default_object_class
            )
        else:
            object_class = str(object_class_raw)

        # Convert dict[str, list[str]] to dict[str, str | list[str]] for ldap3.add
        # ldap3.add accepts dict[str, str | list[str]], and we have dict[str, list[str]]
        # which is compatible (list[str] is a subtype of str | list[str])
        return connection.add(
            dn_str,
            object_class=object_class,
            attributes=attempted_attributes,
        )

    def _extract_undefined_attribute_internal(
        self,
        error_msg: str,
        attempted_attributes: dict[str, list[str]],
    ) -> FlextResult[str]:
        """Extract attribute name from undefined attribute error (internal helper)."""
        error_parts = error_msg.split()
        if len(error_parts) == 0:
            return FlextResult[str].fail("Empty error message")
        problem_attr = error_parts[-1].strip()
        if problem_attr not in attempted_attributes:
            return FlextResult[str].fail(
                f"Attribute '{problem_attr}' not found in attempted attributes"
            )
        return FlextResult[str].ok(problem_attr)

    def _handle_undefined_attribute_error_internal(
        self,
        connection: Connection,
        attempted_attributes: dict[str, list[str]],
        removed_attributes: list[str],
        logger: logging.Logger,
    ) -> bool:
        """Handle undefined attribute error by removing problematic attribute (internal helper)."""
        error_msg = str(connection.last_error).lower()
        if (
            "undefined attribute" not in error_msg
            and "invalid attribute" not in error_msg
        ):
            return False

        problem_attr_result = self._extract_undefined_attribute_internal(
            str(connection.last_error),
            attempted_attributes,
        )
        if problem_attr_result.is_success:
            problem_attr = problem_attr_result.unwrap()
            logger.debug("Removing undefined '%s'", problem_attr)
            del attempted_attributes[problem_attr]  # This modifies the dict in place
            removed_attributes.append(problem_attr)  # Track removed attribute
            return True  # Indicate that an attribute was handled and retry is needed
        return False  # No attribute handled, propagation of error should continue
