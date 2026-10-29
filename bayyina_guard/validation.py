"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

PDF_TYPE = "application/pdf"
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

# extension -> (canonical content type, required leading bytes)
_KINDS = {
    "pdf": (PDF_TYPE, b"%PDF-"),
    "docx": (DOCX_TYPE, b"PK\x03\x04"),
}

# Bidi controls: U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069.
_BIDI_CONTROLS = frozenset(
    ["؜", "‎", "‏"]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
)

# [0-9] (not \d): \d also matches Arabic-Indic and other Unicode digits.
_MATTER_RE = re.compile(r"MAT-[0-9]{4}-[0-9]{5}")


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(raw: object) -> tuple[str | None, str | None, str | None]:
    """Return (display_name, extension, error). Exactly one of (name, ext) / error is set."""
    if not isinstance(raw, str):
        return None, None, "must be a string"
    name = unicodedata.normalize("NFC", raw)
    if not 1 <= len(name) <= 120:
        return None, None, "must be 1 to 120 characters"
    for ch in name:
        if unicodedata.category(ch) == "Cc":
            return None, None, "must not contain control characters"
        if ch in _BIDI_CONTROLS:
            return None, None, "must not contain bidirectional control characters"
    if "/" in name or "\\" in name:
        return None, None, "must not contain path separators"
    if ".." in name:
        return None, None, "must not contain '..'"
    if name.startswith("."):
        return None, None, "must not start with '.'"
    stem, dot, ext = name.rpartition(".")
    if not dot:
        return None, None, "must have a .pdf or .docx extension"
    ext = ext.lower()
    if ext not in _KINDS:
        return None, None, "extension must be pdf or docx"
    if not stem.strip():
        return None, None, "must have a name before the extension"
    return name, ext, None


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    if not isinstance(meta, dict):
        raise ValidationError({k: "missing" for k in
                               ("filename", "content_type", "size_bytes", "matter_id", "first_bytes")})

    errors: dict[str, str] = {}

    display_name, ext, fn_err = _check_filename(meta.get("filename"))
    if fn_err is not None:
        errors["filename"] = fn_err

    content_type = meta.get("content_type")
    first_bytes = meta.get("first_bytes")

    if not isinstance(content_type, str):
        errors["content_type"] = "must be a string"
    elif ext is not None and content_type != _KINDS[ext][0]:
        errors["content_type"] = f"must be {_KINDS[ext][0]} for a .{ext} file"

    if not isinstance(first_bytes, bytes):
        errors["first_bytes"] = "must be bytes"
    elif ext is not None and not first_bytes.startswith(_KINDS[ext][1]):
        errors["first_bytes"] = f"does not look like a .{ext} file"

    size = meta.get("size_bytes")
    if isinstance(size, bool) or not isinstance(size, int):
        errors["size_bytes"] = "must be an integer"
    elif not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = f"must be between 1 and {MAX_BYTES} bytes"

    matter_id = meta.get("matter_id")
    if (not isinstance(matter_id, str) or not matter_id.isascii()
            or _MATTER_RE.fullmatch(matter_id) is None):
        errors["matter_id"] = "must look like MAT-0000-00000"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=uuid.uuid4().hex + "." + ext,
        display_name=display_name,
        extension=ext,
        content_type=_KINDS[ext][0],
        size_bytes=size,
        matter_id=matter_id,
    )
