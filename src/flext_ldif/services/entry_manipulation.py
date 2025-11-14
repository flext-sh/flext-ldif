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
from typing import cast

from flext_core import FlextResult, FlextRuntime
from flext_ldap.constants import FlextLdapConstants
from ldap3 import Connection, LDAPAttributeError, LDAPObjectClassError

from flext_ldif import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation


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
        entry: FlextLdifModels.Entry, attr_name: str
    ) -> object | None:
        """Safely get attribute value from LDAP entry.

        Args:
            entry: LDAP entry to extract attribute from.
            attr_name: Name of the attribute to retrieve.

        Returns:
            Attribute value or None if not found.

        """
        if not entry.attributes or not hasattr(entry.attributes, "attributes"):
            return None
        attr_dict = entry.attributes.attributes
        if not isinstance(attr_dict, dict):
            return None
        return attr_dict.get(attr_name)

    @staticmethod
    def normalize_attribute_value(attr_value: object | None) -> str | None:
        """Normalize LDAP attribute value to string.

        Args:
            attr_value: Raw LDAP attribute value (list or single value).

        Returns:
            Normalized string value or None if invalid/empty.

        """
        if attr_value is None:
            return None

        if FlextRuntime.is_list_like(attr_value) and len(attr_value) > 0:
            return str(attr_value[0])

        try:
            str_value = str(attr_value).strip()
            return str_value or None
        except (TypeError, AttributeError):
            return None

    @staticmethod
    def get_normalized_attribute(
        entry: FlextLdifModels.Entry, attr_name: str
    ) -> str | None:
        """Get and normalize LDAP attribute value.

        Args:
            entry: LDAP entry to extract attribute from.
            attr_name: Name of the attribute to retrieve and normalize.

        Returns:
            Normalized string value or None if not found/invalid.

        """
        raw_value = EntryManipulationServices.get_entry_attribute(entry, attr_name)
        return EntryManipulationServices.normalize_attribute_value(raw_value)

    @staticmethod
    def build_display_name_from_parts(
        given_name: str | None,
        sn: str | None,
    ) -> str | None:
        """Build display name from given name and surname parts.

        Args:
            given_name: User's given/first name.
            sn: User's surname/last name.

        Returns:
            Formatted full name or None if insufficient parts.

        """
        if given_name and sn:
            return f"{given_name} {sn}"
        return None

    def get_display_name_priority_list(
        self, user: FlextLdifModels.Entry
    ) -> list[str | None]:
        """Get prioritized list of display name candidates.

        Args:
            user: LDAP user entry.

        Returns:
            Ordered list of display name candidates (first non-None wins).

        """
        return [
            self.get_normalized_attribute(user, "displayName"),
            self.build_display_name_from_parts(
                self.get_normalized_attribute(user, "givenName"),
                self.get_normalized_attribute(user, "sn"),
            ),
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

        for option in display_options:
            if option:
                return option

        return FlextLdapConstants.ErrorStrings.UNKNOWN_USER

    def check_lock_attributes(self, user: FlextLdifModels.Entry) -> str | None:
        """Check user lock attributes.

        Args:
            user: LDAP user entry to check.

        Returns:
            Status string if locked/disabled, None if active.

        """
        lock_attrs = FlextLdapConstants.LockAttributes.ALL_LOCK_ATTRIBUTES

        for attr in lock_attrs:
            attr_value = self.get_entry_attribute(user, attr)
            if attr_value is None:
                continue

            normalized_value = self.normalize_attribute_value(attr_value)
            if not normalized_value:
                continue

            if normalized_value.lower() in {
                FlextLdapConstants.BooleanStrings.TRUE.lower(),
                FlextLdapConstants.BooleanStrings.ONE,
                FlextLdapConstants.BooleanStrings.YES.lower(),
            }:
                return FlextLdapConstants.UserStatus.LOCKED

            try:
                if (
                    int(normalized_value)
                    & FlextLdapConstants.ActiveDirectoryFlags.ADS_UF_ACCOUNTDISABLE
                ):
                    return FlextLdapConstants.UserStatus.DISABLED
            except (ValueError, TypeError):
                continue

        return None

    def check_password_expiry(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user password is expired.

        Args:
            user: LDAP user entry to check.

        Returns:
            True if password is considered expired (simplified check).

        """
        pwd_last_set = self.get_entry_attribute(
            user, FlextLdapConstants.ActiveDirectoryAttributes.PWD_LAST_SET
        )
        return pwd_last_set is not None

    def determine_user_status(self, user: FlextLdifModels.Entry) -> str:
        """Determine user status based on LDAP attributes.

        Args:
            user: LDAP user entry.

        Returns:
            User status string ("active", "locked", "disabled").

        """
        lock_status = self.check_lock_attributes(user)
        if lock_status:
            return lock_status

        if self.check_password_expiry(user):
            return FlextLdapConstants.UserStatus.ACTIVE

        return FlextLdapConstants.UserStatus.ACTIVE

    def check_group_email_requirement(
        self,
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
    ) -> str | None:
        """Check if group requires email membership.

        Args:
            user: LDAP user entry.
            group: LDAP group entry.

        Returns:
            Error message if requirement not met, None if valid.

        """
        group_cn = self.get_normalized_attribute(group, "cn")
        user_email = self.get_normalized_attribute(user, "mail")

        if group_cn and "REDACTED_LDAP_BIND_PASSWORD" in group_cn.lower() and not user_email:
            return "Admin group members must have email addresses"

        return None

    def check_user_active_status(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user is active (not locked).

        Args:
            user: LDAP user entry.

        Returns:
            True if user is active, False if locked.

        """
        lock_status = self.check_lock_attributes(user)
        return lock_status is None

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
        email_error = self.check_group_email_requirement(user, group)
        if email_error:
            return FlextResult[bool].fail(email_error)

        if not self.check_user_active_status(user):
            return FlextResult[bool].fail("Inactive users cannot be added to groups")

        return FlextResult[bool].ok(True)

    def normalize_username_base(
        self, base_name: str, validation_service: FlextLdifValidation
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
            FlextLdapConstants.RegexPatterns.USERNAME_SANITIZE_PATTERN,
            "",
            username,
        )

        if not username:
            return FlextResult[str].fail("Base name contains no valid characters")

        validation_result = validation_service.validate_attribute_name(username)
        if validation_result.is_failure or not validation_result.unwrap():
            return FlextResult[str].fail(
                f"Generated username '{username}' does not meet LDAP attribute name requirements"
            )

        return FlextResult[str].ok(username)

    def collect_existing_uids(
        self, existing_users: list[FlextLdifModels.Entry]
    ) -> set[str]:
        """Collect existing UIDs from user entries.

        Args:
            existing_users: List of existing LDAP user entries.

        Returns:
            Set of normalized existing UIDs.

        """
        existing_uids = set()
        for user in existing_users:
            uid_value = self.get_normalized_attribute(user, "uid")
            if uid_value:
                existing_uids.add(uid_value)
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
            f"Could not generate unique username after {max_attempts} attempts"
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
            base_name, validation_service or self._validation_service
        )
        if normalized_result.is_failure:
            return normalized_result

        base_username = normalized_result.unwrap()

        existing_uids = self.collect_existing_uids(existing_users)

        return self.generate_username_with_suffix(
            base_username, existing_uids, max_attempts
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
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
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
            effectives_mode = (
                quirks_mode or FlextLdapConstants.Types.QuirksMode.AUTOMATIC
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
            max_retries = (
                1 if effectives_mode == FlextLdapConstants.Types.QuirksMode.RFC else 20
            )
            retry_count = 0

            logger.debug(
                "Adding entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            while retry_count < max_retries:
                try:
                    success = self._attempt_add_entry_internal(
                        connection, dn_str, attempted_attributes
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

                except (
                    LDAPAttributeError,
                    LDAPObjectClassError,
                ) as e:
                    error_str = str(e).lower()
                    if (
                        "undefined attribute" in error_str
                        or "invalid attribute" in error_str
                    ):
                        problem_attr = self._extract_undefined_attribute_internal(
                            str(e),
                            attempted_attributes,
                        )
                        if problem_attr:
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
        object_class_raw = attempted_attributes.get(
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
            [FlextLdapConstants.Defaults.OBJECT_CLASS_TOP],
        )
        if FlextRuntime.is_list_like(object_class_raw):
            object_class = (
                str(object_class_raw[0])
                if object_class_raw
                else FlextLdapConstants.Defaults.OBJECT_CLASS_TOP
            )
        else:
            object_class = str(object_class_raw)

        typed_conn = connection
        # Cast to dict[str, str | list[str]] for ldap3.add method signature
        attrs_for_add = cast("dict[str, str | list[str]]", attempted_attributes)
        return typed_conn.add(
            dn_str, object_class=object_class, attributes=attrs_for_add
        )

    def _extract_undefined_attribute_internal(
        self,
        error_msg: str,
        attempted_attributes: dict[str, list[str]],
    ) -> str | None:
        """Extract attribute name from undefined attribute error (internal helper)."""
        error_parts = error_msg.split()
        if len(error_parts) > 0:
            problem_attr = error_parts[-1].strip()
            if problem_attr in attempted_attributes:
                return problem_attr
        return None

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

        problem_attr = self._extract_undefined_attribute_internal(
            str(connection.last_error),
            attempted_attributes,
        )
        if problem_attr:
            logger.debug("Removing undefined '%s'", problem_attr)
            del attempted_attributes[problem_attr]  # This modifies the dict in place
            removed_attributes.append(problem_attr)  # Track removed attribute
            return True  # Indicate that an attribute was handled and retry is needed
        return False  # No attribute handled, propagation of error should continue
