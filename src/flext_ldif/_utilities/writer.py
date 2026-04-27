"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)

from flext_ldif import c, m


class FlextLdifUtilitiesWriter:
    """Pure LDIF Formatting Operations - No Models, No Side Effects."""

    @staticmethod
    def add_attribute_flags(
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
    ) -> None:
        """Add flags to attribute parts list."""
        if attr_data.single_value:
            parts.append("SINGLE-VALUE")
        if attr_data.metadata and attr_data.metadata.extensions.get(
            c.Ldif.COLLECTIVE,
        ):
            parts.append("COLLECTIVE")
        if attr_data.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
    ) -> None:
        """Add matching rules to attribute parts list."""
        if attr_data.equality:
            parts.append(f"EQUALITY {attr_data.equality}")
        if attr_data.ordering:
            parts.append(f"ORDERING {attr_data.ordering}")
        if attr_data.substr:
            parts.append(f"SUBSTR {attr_data.substr}")

    @staticmethod
    def add_attribute_syntax(
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
    ) -> None:
        """Add syntax and length to attribute parts list."""
        if attr_data.syntax:
            syntax_str = str(attr_data.syntax)
            if attr_data.length is not None:
                syntax_str += f"{{{attr_data.length}}}"
            parts.append(f"SYNTAX {syntax_str}")

    @staticmethod
    def finalize_ldif_text(ldif_lines: MutableSequence[str]) -> str:
        """Join LDIF lines and ensure proper trailing newline."""
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and (not ldif_text.endswith("\n")):
            ldif_text += "\n"
        return ldif_text

    @staticmethod
    def fold_line(
        line: str,
        width: int = c.Ldif.LINE_FOLD_WIDTH,
    ) -> MutableSequence[str]:
        """Fold long LDIF line according to RFC 2849 §3."""
        if not line:
            return [line]
        line_bytes = line.encode(c.Ldif.DEFAULT_ENCODING)
        if len(line_bytes) <= width:
            return [line]
        folded: MutableSequence[str] = []
        pos = 0
        while pos < len(line_bytes):
            if not folded:
                chunk_end = min(pos + width, len(line_bytes))
            else:
                chunk_end = min(pos + width - 1, len(line_bytes))
            while chunk_end > pos:
                try:
                    chunk = line_bytes[pos:chunk_end].decode(c.Ldif.DEFAULT_ENCODING)
                    break
                except UnicodeDecodeError:
                    chunk_end -= 1
            else:
                chunk_end = pos + 1
                chunk = line_bytes[pos:chunk_end].decode(
                    c.Ldif.DEFAULT_ENCODING, errors="replace"
                )
            if folded:
                folded.append(c.Ldif.LINE_CONTINUATION_SPACE + chunk)
            else:
                folded.append(chunk)
            pos = chunk_end
        return folded

    @staticmethod
    def is_safe_char(char: str) -> bool:
        """Check if char is SAFE-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        return (
            c.Ldif.SAFE_CHAR_MIN <= code <= c.Ldif.SAFE_CHAR_MAX
            and code not in c.Ldif.SAFE_CHAR_EXCLUDE
        )

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        if not FlextLdifUtilitiesWriter.is_safe_char(char):
            return False
        return code not in c.Ldif.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def needs_base64_encoding(value: str, *, check_trailing_space: bool = True) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2."""
        if not value:
            return False
        if value[0] in c.Ldif.BASE64_START_CHARS:
            return True
        if check_trailing_space and value[-1] == " ":
            return True
        for char in value:
            byte_val = ord(char)
            if (
                byte_val < c.Ldif.SAFE_CHAR_MIN
                or byte_val > c.Ldif.SAFE_CHAR_MAX
                or byte_val in c.Ldif.SAFE_CHAR_EXCLUDE
            ):
                return True
        return False


__all__: list[str] = ["FlextLdifUtilitiesWriter"]
