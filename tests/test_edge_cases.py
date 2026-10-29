"""My own edge-case tests (the public tests are only a smoke test)."""
import base64
import hashlib
import itertools
import re
import time
import unicodedata

import pytest

from bayyina_guard.passwords import hash_password, needs_rehash, verify_password
from bayyina_guard.policy import Document, User, authorize, visible_documents
from bayyina_guard.validation import MAX_BYTES, ValidationError, validate_upload

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def meta(**over):
    m = {"filename": "عقد.pdf", "content_type": PDF, "size_bytes": 10,
         "matter_id": "MAT-2026-00042", "first_bytes": b"%PDF-1.7"}
    m.update(over)
    return m


def errors_of(**over):
    with pytest.raises(ValidationError) as exc:
        validate_upload(meta(**over))
    return exc.value.errors


# ---------- validation ----------

@pytest.mark.parametrize("name", [
    "..\\x.pdf", "/abs.pdf", "a/b.pdf", ".hidden.pdf", "x..pdf", "x.pdf/",
    "a\x00b.pdf", "a\nb.pdf", "a⁦b.pdf", "a‮b.pdf", "a؜b.pdf",
    "عق‫د.pdf", "a‎b.pdf", "a‏b.pdf",
    "x.pdf.exe", "x.", "pdf", ".pdf", " .pdf", "", "a" * 117 + ".pdf", 5, None,
])
def test_bad_filenames(name):
    assert "filename" in errors_of(filename=name)


@pytest.mark.parametrize("name", ["LEASE.PDF", "x.exe.pdf", "a b.pdf", "a" * 116 + ".pdf"])
def test_good_filenames(name):
    assert validate_upload(meta(filename=name)).extension == "pdf"


def test_docx_cases():
    ok = validate_upload(meta(filename="x.DOCX", content_type=DOCX, first_bytes=b"PK\x03\x04zz"))
    assert ok.content_type == DOCX and ok.extension == "docx"
    # docx sent as pdf type
    assert "content_type" in errors_of(filename="x.docx", first_bytes=b"PK\x03\x04")
    # docx type with pdf bytes: first_bytes error, not content_type
    e = errors_of(filename="x.docx", content_type=DOCX)
    assert "first_bytes" in e and "content_type" not in e


def test_invalid_filename_only_type_checks_the_rest():
    e = errors_of(filename="x.exe", content_type="text/plain", first_bytes=b"zzz")
    assert set(e) == {"filename"}
    e = errors_of(filename="x.exe", content_type=3, first_bytes="str")
    assert set(e) == {"filename", "content_type", "first_bytes"}


@pytest.mark.parametrize("size", [True, False, 10.0, 0, -1, "10", None, MAX_BYTES + 1])
def test_bad_sizes(size):
    assert "size_bytes" in errors_of(size_bytes=size)


@pytest.mark.parametrize("size", [1, MAX_BYTES])
def test_good_sizes(size):
    assert validate_upload(meta(size_bytes=size)).size_bytes == size


@pytest.mark.parametrize("mid", [
    "MAT-٢٠٢٦-٠٠٠٤٢", "MAT-2026-00042\n", " MAT-2026-00042", "mat-2026-00042",
    "MAT-202-00042", "MAT-2026-0004", "MAT-2026-000421", "42", "", None, 5,
])
def test_bad_matter_ids(mid):
    assert "matter_id" in errors_of(matter_id=mid)


def test_nfc_and_unique_stored_names():
    nfd = unicodedata.normalize("NFD", "café.pdf")
    assert nfd != "café.pdf"
    assert validate_upload(meta(filename=nfd)).display_name == unicodedata.normalize("NFC", nfd)
    names = {validate_upload(meta(filename="café.pdf")).stored_name for _ in range(50)}
    assert len(names) == 50
    assert all(re.fullmatch(r"[0-9a-f]{32}\.pdf", n) for n in names)


def test_length_is_measured_after_nfc():
    # 60 decomposed "é" (120 code points) compose to 60 characters
    nfd = unicodedata.normalize("NFD", "é" * 60) + ".pdf"
    assert validate_upload(meta(filename=nfd)).display_name == "é" * 60 + ".pdf"


# ---------- policy ----------

DOC = Document("d", "CL-A", "MAT-1")


def u(role, **kw):
    return User(id="u1", role=role, **kw)


def test_deny_by_default():
    assert authorize(None, "read", DOC).reason == "unauthenticated"
    assert authorize(User("", "partner"), "read", DOC).reason == "unauthenticated"
    assert authorize(u("partner"), "peek", DOC).reason == "unknown_action"
    assert authorize(u("intern"), "read", DOC).reason == "unknown_role"
    for a in ("read", "comment", "upload_version", "delete", "share_external"):
        assert authorize(u("auditor"), a, DOC).reason == "role_not_permitted"


def test_precedence():
    held = Document("d", "CL-A", "MAT-1", legal_hold=True)
    assert authorize(u("partner", mfa=True), "delete", held).reason == "legal_hold"
    assert authorize(u("auditor"), "delete", held).reason == "legal_hold"
    assert authorize(u("client", client_id="CL-B"), "delete", DOC).reason == "role_not_permitted"
    r = Document("d", "CL-A", "MAT-1", confidentiality="restricted")
    assert authorize(u("client", client_id="CL-B"), "read", r).reason == "tenant_mismatch"
    assert authorize(u("associate"), "read", r).reason == "not_assigned"
    assert authorize(u("client", client_id="CL-A"), "read", r).reason == "restricted"


def test_assignment_restricted_and_mfa():
    m = frozenset({"MAT-1"})
    r = Document("d", "CL-A", "MAT-1", confidentiality="restricted")
    assert authorize(u("associate", matters=m), "read", r).reason == "mfa_required"
    assert authorize(u("associate", matters=m, mfa=True), "read", r).allowed
    assert authorize(u("paralegal", matters=m, mfa=True), "comment", DOC).reason == "role_not_permitted"
    assert authorize(u("paralegal", matters=m, mfa=True), "read", r).reason == "restricted"
    assert authorize(u("partner"), "share_external", DOC).reason == "mfa_required"
    assert authorize(u("partner", mfa=True), "share_external", DOC).allowed
    odd = Document("d", "CL-A", "MAT-1", confidentiality="secret")
    assert authorize(u("partner"), "read", odd).reason == "mfa_required"


def test_tenant_isolation_exhaustive():
    ids = [None, "", "CL-A", "cl-a", "CL-A ", "CL-B"]
    actions = ["read", "comment", "upload_version", "delete", "share_external", "x"]
    for cid, dcid, act, conf, mfa, hold in itertools.product(
            ids, ["CL-A"], actions, ["normal", "restricted", "", "Normal"], [True, False], [True, False]):
        d = authorize(User("u", "client", client_id=cid, mfa=mfa), act, Document("d", dcid, "M", conf, hold))
        if d.allowed:
            assert cid == dcid and conf == "normal" and act in ("read", "comment")


def test_visible_documents_matches_authorize_and_keeps_order():
    docs = [Document(str(i), c, "MAT-1", conf)
            for i, (c, conf) in enumerate(itertools.product(["CL-A", "CL-B", "cl-a"], ["normal", "restricted"]))]
    users = [None, u("client", client_id="CL-A"), u("partner", mfa=True), u("partner"),
             u("associate", matters=frozenset({"MAT-1"})), u("auditor")]
    for user in users:
        assert visible_documents(user, docs) == [d for d in docs if authorize(user, "read", d).allowed]


# ---------- passwords ----------

def enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make(n, r, p, pw="correct horse", salt=b"s" * 16, dklen=32):
    key = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=64 * 1024 * 1024)
    return f"scrypt${n}${r}${p}${enc(salt)}${enc(key)}"


def test_format_and_randomness():
    a, b = hash_password("password-123"), hash_password("password-123")
    assert a != b
    scheme, n, r, p, salt, key = a.split("$")
    assert (scheme, n, r, p) == ("scrypt", "16384", "8", "5")
    assert "=" not in a
    assert len(base64.urlsafe_b64decode(salt + "==")) == 16
    assert len(base64.urlsafe_b64decode(key + "==")) == 32


def test_unicode_normalisation_and_limits():
    nfc = "café-مرحبا"
    nfd = unicodedata.normalize("NFD", nfc)
    h = hash_password(nfc)
    assert verify_password(nfd, h)
    assert verify_password(nfc, hash_password(nfd))
    with pytest.raises(ValueError):
        hash_password("a" * 7)
    with pytest.raises(ValueError):
        hash_password("a" * 129)
    hash_password("a" * 8)
    hash_password("a" * 128)
    for bad in (b"password123", None, 12345678):
        with pytest.raises(TypeError):
            hash_password(bad)


def test_legacy_hash_verifies_and_needs_rehash():
    legacy = make(4096, 8, 1)
    assert verify_password("correct horse", legacy)
    assert not verify_password("wrong horse", legacy)
    assert needs_rehash(legacy)
    assert not needs_rehash(make(2 ** 14, 8, 5))
    assert needs_rehash("garbage")


def test_malformed_is_false():
    good = make(2 ** 14, 8, 5)
    salt, key = good.split("$")[4:]
    bad = [
        "", "scrypt", "$", good[:-4], good + "$x", "bcrypt$" + good[7:], None, 123, b"scrypt",
        f"scrypt$16384$8$5${salt}$!!!!", f"scrypt$16384$8$5${salt}={key}",
        f"scrypt$16384$8$5${salt}${key}=", f"scrypt$٣٢$8$5${salt}${key}",
        f"scrypt$ 16384$8$5${salt}${key}", f"scrypt$-16384$8$5${salt}${key}",
        make(2 ** 14, 8, 5, salt=b"s" * 15), make(2 ** 14, 8, 5, dklen=31), make(2 ** 14, 8, 5, dklen=33),
        make(1, 8, 5) if False else f"scrypt$1$8$5${salt}${key}",
        f"scrypt$16383$8$5${salt}${key}", f"scrypt$0$8$5${salt}${key}",
        f"scrypt${2 ** 21}$8$5${salt}${key}", f"scrypt$16384$0$5${salt}${key}",
        f"scrypt$16384$33$5${salt}${key}", f"scrypt$16384$8$0${salt}${key}",
        f"scrypt$16384$8$17${salt}${key}",
    ]
    for s in bad:
        assert verify_password("correct horse", s) is False, s


def test_hash_truncated_by_four_chars_is_rejected():
    good = make(2 ** 14, 8, 5)
    assert verify_password("correct horse", good)
    assert not verify_password("correct horse", good[:-4])
    # a 28-byte key where the first 28 bytes are the genuine key prefix
    salt = b"s" * 16
    full = hashlib.scrypt(b"correct horse", salt=salt, n=2 ** 14, r=8, p=5, dklen=32, maxmem=64 * 1024 * 1024)
    short = f"scrypt$16384$8$5${enc(salt)}${enc(full[:28])}"
    assert not verify_password("correct horse", short)


def test_dos_parameters_return_quickly():
    salt, key = make(2 ** 14, 8, 5).split("$")[4:]
    start = time.monotonic()
    for s in (f"scrypt$16384$8$99999999${salt}${key}", f"scrypt$16384$8$4294967296${salt}${key}",
              f"scrypt$16384$99999$5${salt}${key}", f"scrypt${2 ** 62}$8$5${salt}${key}",
              f"scrypt$16384$8${'9' * 5000}${salt}${key}"):
        assert verify_password("correct horse", s) is False
    assert time.monotonic() - start < 5


def test_verify_non_string_password_is_false():
    assert verify_password(None, make(4096, 8, 1)) is False
    assert verify_password(b"correct horse", make(4096, 8, 1)) is False
