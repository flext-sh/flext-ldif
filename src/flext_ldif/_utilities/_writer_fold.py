"""LDIF line folding utilities per RFC 2849 §3.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifWriterLineFolding:
    """Fold long LDIF lines into continuation lines without splitting tokens."""

    _KEYWORD_TOKEN_MAX_LENGTH: int = 12

    class Fold:
        """Folding cursor: where the walk stands in the raw byte line."""

        def __init__(
            self,
            line_bytes: bytes,
            pos: int = 0,
            chunk_end: int = 0,
            is_first: bool = True,
        ) -> None:
            """Bind the walk state.

            Args:
                line_bytes: The raw encoded LDIF line.
                pos: Byte offset the current chunk starts at.
                chunk_end: Byte offset the current chunk was cut at.
                is_first: Whether the chunk is the unfolded first chunk.
            """
            self.line_bytes = line_bytes
            self.pos = pos
            self.chunk_end = chunk_end
            self.is_first = is_first

        def advance(self, chunk_end: int) -> None:
            """Move the cursor to the next chunk after ``chunk_end``."""
            self.pos = chunk_end
            self.chunk_end = chunk_end
            self.is_first = False

    @classmethod
    def _initial_chunk_end(cls, fold: Fold, width: int) -> int:
        """Compute the byte end of the next chunk before whitespace preference.

        Returns:
            The resulting ``int``.
        """
        span = width if fold.is_first else width - 1
        return min(fold.pos + span, len(fold.line_bytes))

    @classmethod
    def _decode_chunk(cls, fold: Fold) -> tuple[str, int]:
        """Decode the widest valid character chunk at the cursor.

        Shrinks the chunk on ``UnicodeDecodeError`` until it decodes; when no
        character fits, decodes one byte with replacement.

        Returns:
            The resulting ``tuple[str, int]``.
        """
        line_bytes = fold.line_bytes
        pos = fold.pos
        chunk_end = fold.chunk_end
        while chunk_end > pos:
            try:
                chunk = line_bytes[pos:chunk_end].decode(c.Ldif.DEFAULT_ENCODING)
                return (chunk, chunk_end)
            except UnicodeDecodeError:
                chunk_end -= 1
        return (
            line_bytes[pos : pos + 1].decode(
                c.Ldif.DEFAULT_ENCODING,
                errors="replace",
            ),
            pos + 1,
        )

    @staticmethod
    def _keyword_prefix_end(chunk: str, separator_index: int) -> int:
        """Extend past ``:``/``<`` value-spec markers and following spaces.

        Returns:
            The resulting ``int``.
        """
        prefix_end = separator_index + 1
        while prefix_end < len(chunk) and chunk[prefix_end] in {":", "<"}:
            prefix_end += 1
        while (
            prefix_end < len(chunk)
            and chunk[prefix_end] == c.Ldif.LINE_CONTINUATION_SPACE
        ):
            prefix_end += 1
        return prefix_end

    @staticmethod
    def _initial_split_index(chunk: str, *, is_first: bool) -> int:
        """Locate the last whitespace split candidate, protecting keyword prefixes.

        Returns:
            The resulting ``int``.
        """
        split_index = max(
            chunk.rfind(c.Ldif.LINE_CONTINUATION_SPACE),
            chunk.rfind("\t"),
        )
        if not is_first:
            return split_index
        separator_index = chunk.find(":")
        if separator_index >= 0:
            prefix_end = FlextLdifWriterLineFolding._keyword_prefix_end(
                chunk,
                separator_index,
            )
            if split_index < prefix_end:
                split_index = -1
        return split_index

    @staticmethod
    def _adjust_split_for_keyword_token(
        chunk: str,
        split_index: int,
        keyword_token_max_length: int,
    ) -> int:
        """Move the split before an all-uppercase keyword token when possible.

        Returns:
            The resulting ``int``.
        """
        left_text = chunk[:split_index].rstrip()
        right_text = chunk[split_index + 1 :].lstrip()
        left_parts = left_text.rsplit(None, 1)
        if not (left_parts and right_text):
            return split_index
        left_token = left_parts[-1]
        if not (left_token.isupper() and len(left_token) <= keyword_token_max_length):
            return split_index
        earlier_space = left_text.rfind(c.Ldif.LINE_CONTINUATION_SPACE)
        earlier_tab = left_text.rfind("\t")
        earlier_split = max(earlier_space, earlier_tab)
        return earlier_split if earlier_split > 0 else split_index

    @classmethod
    def _prefer_whitespace_split(
        cls,
        fold: Fold,
        chunk: str,
    ) -> tuple[str, int]:
        """Adjust the chunk to fold at whitespace instead of splitting tokens.

        Returns:
            The resulting ``tuple[str, int]``.
        """
        if fold.chunk_end >= len(fold.line_bytes):
            return (chunk, fold.chunk_end)
        split_index = cls._initial_split_index(
            chunk,
            is_first=fold.is_first,
        )
        if split_index > 0:
            split_index = cls._adjust_split_for_keyword_token(
                chunk,
                split_index,
                cls._KEYWORD_TOKEN_MAX_LENGTH,
            )
        split_chunk = chunk[: split_index + 1]
        split_bytes = split_chunk.encode(c.Ldif.DEFAULT_ENCODING)
        if split_bytes:
            return (split_chunk, fold.pos + len(split_bytes))
        return (chunk, fold.chunk_end)

    @classmethod
    def fold_line(
        cls,
        line: str,
        width: int = c.Ldif.LINE_FOLD_WIDTH,
    ) -> t.MutableSequenceOf[str]:
        """Fold long LDIF line according to RFC 2849 §3.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not line:
            return [line]
        line_bytes = line.encode(c.Ldif.DEFAULT_ENCODING)
        if len(line_bytes) <= width:
            return [line]
        folded: t.MutableSequenceOf[str] = []
        fold = cls.Fold(line_bytes)
        while fold.pos < len(line_bytes):
            fold.chunk_end = cls._initial_chunk_end(fold, width)
            chunk, chunk_end = cls._decode_chunk(fold)
            chunk, chunk_end = cls._prefer_whitespace_split(fold, chunk)
            if folded:
                folded.append(c.Ldif.LINE_CONTINUATION_SPACE + chunk)
            else:
                folded.append(chunk)
            fold.advance(chunk_end)
        return folded


__all__: list[str] = ["FlextLdifWriterLineFolding"]
