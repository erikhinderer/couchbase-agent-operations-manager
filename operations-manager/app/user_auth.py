"""
Local dashboard login for the Couchbase Agent Operations Manager.

This is a separate concern from the agent RBAC in app/rbac_policy.py and
the `identities` collection in app/couchbase_client.py: that system
authenticates *agents* calling /v1/tools/discover and /v1/tools/invoke
with a bearer API key. This module authenticates *people* opening the
dashboard in a browser - the Servers, Catalog, Roles, Threat Detection,
Insights, Audit Log, LLM Caching, and Settings pages - via a login page
and a signed session cookie.

Three things live here:

  1. Password hashing (bcrypt) and session tokens (JWT, HS256) for local
     accounts stored in Couchbase's `users` collection.
  2. Symmetric encryption (Fernet, keyed off config.AUTH_SECRET_KEY) for
     the one dashboard secret that has to be stored *reversibly* rather
     than hashed: the LDAP bind password, which the appliance needs to
     hand back to the directory on every login attempt.
  3. The LDAP authentication flow itself, via ldap3: bind as the service
     account, search for the user, then bind again as that user's own DN
     with the password they typed in to actually verify it.

UI_ROLES stays code-defined for the same reason ROLES does in
rbac_policy.py - it's the kind of thing that gets reviewed, not something
end users type into a text box. "admin" gets the Settings section (local
accounts, roles, LDAP) plus every other page; "user" gets everything
except Settings.
"""
import asyncio
import base64
import hashlib
import logging
import os
import shutil
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import jwt
import ldap3
from ldap3.utils.conv import escape_filter_chars
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization

from config import (
    AUTH_SECRET_KEY,
    AUTH_SESSION_TTL_HOURS,
    TLS_CERT_DEFAULT_BACKUP,
    TLS_CERT_FILE,
    TLS_KEY_DEFAULT_BACKUP,
    TLS_KEY_FILE,
)

logger = logging.getLogger("operations-manager.user_auth")

# ---------------------------------------------------------------------------
# UI roles (distinct from the agent RBAC roles in rbac_policy.ROLES)
# ---------------------------------------------------------------------------
UI_ROLES = {
    "admin": "Full access, including Settings (local accounts, roles, LDAP).",
    "user": "Every dashboard page except Settings.",
}
DEFAULT_LOCAL_ROLE = "user"
MIN_PASSWORD_LENGTH = 8


def password_policy_error(password: str) -> str | None:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None


# ---------------------------------------------------------------------------
# Passwords - bcrypt, one-way. Nothing that verifies a password is ever
# capable of recovering it - that's the point of a hash over encryption
# for this particular secret.
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # A malformed/legacy hash should fail closed, not raise.
        logger.warning("verify_password: malformed hash")
        return False


# ---------------------------------------------------------------------------
# Sessions - a signed JWT carried in an httpOnly cookie (see main.py). It's
# stateless on purpose: nothing to look up in Couchbase on every request,
# and every issued session invalidates itself simply by expiring or by
# AUTH_SECRET_KEY changing.
# ---------------------------------------------------------------------------
SESSION_COOKIE_NAME = "aom_session"
_JWT_ALGORITHM = "HS256"


def create_session_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + AUTH_SESSION_TTL_HOURS * 3600,
    }
    return jwt.encode(payload, AUTH_SECRET_KEY, algorithm=_JWT_ALGORITHM)


def decode_session_token(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=[_JWT_ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if not username or not role:
            return None
        return {"username": username, "role": role}
    except jwt.PyJWTError as exc:
        logger.debug("decode_session_token failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Encryption at rest for the LDAP bind password. Fernet needs a 32-byte
# urlsafe-base64 key; AUTH_SECRET_KEY is an arbitrary operator-supplied
# string (typically a hex token generated by start.sh), so it's stretched
# into a Fernet key with SHA-256 rather than requiring a second secret to
# be generated and managed.
# ---------------------------------------------------------------------------
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        digest = hashlib.sha256(AUTH_SECRET_KEY.encode("utf-8")).digest()
        _fernet = Fernet(base64.urlsafe_b64encode(digest))
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("decrypt_secret: could not decrypt stored value (did AUTH_SECRET_KEY change?)")
        return ""


# ---------------------------------------------------------------------------
# LDAP configuration - stored in Couchbase at settings::ldap (see
# config.LDAP_SETTINGS_DOC), the same settings::<name> convention as
# settings::llm_cache. The bind password is the only field encrypted at
# rest here; everything else is operational config, not a secret.
# ---------------------------------------------------------------------------
DEFAULT_LDAP_CONFIG = {
    "enabled": False,
    "host": "",
    "port": 389,
    "use_ssl": False,
    "start_tls": False,
    "bind_dn": "",
    "bind_password_encrypted": "",
    "user_search_base": "",
    "user_search_filter": "(uid={username})",
    "admin_group_dn": "",
    "group_member_attribute": "memberOf",
    # PEM-encoded corporate CA certificate (or chain) used to validate the
    # directory's LDAPS/StartTLS certificate. Not a secret - a CA cert is
    # public by design - so unlike bind_password_encrypted it is stored (and
    # may be returned over the API) as plain text. Empty means "use ldap3's
    # default TLS behavior", which is the same permissive (no verification)
    # mode this appliance has always used for LDAPS/StartTLS, so leaving
    # this unset is not a regression for existing deployments.
    "ca_certificate": "",
}


def normalize_ldap_config(cfg: dict | None) -> dict:
    """Merge partial input over the defaults and coerce types - the same
    role llm_cache.normalize_config plays for the LLM Caching page."""
    merged = {**DEFAULT_LDAP_CONFIG, **(cfg or {})}
    return {
        "enabled": bool(merged.get("enabled", False)),
        "host": str(merged.get("host") or "").strip(),
        "port": int(merged.get("port") or 389),
        "use_ssl": bool(merged.get("use_ssl", False)),
        "start_tls": bool(merged.get("start_tls", False)),
        "bind_dn": str(merged.get("bind_dn") or "").strip(),
        "bind_password_encrypted": str(merged.get("bind_password_encrypted") or ""),
        "user_search_base": str(merged.get("user_search_base") or "").strip(),
        "user_search_filter": str(merged.get("user_search_filter") or "(uid={username})").strip(),
        "admin_group_dn": str(merged.get("admin_group_dn") or "").strip(),
        "group_member_attribute": str(merged.get("group_member_attribute") or "memberOf").strip(),
        "ca_certificate": str(merged.get("ca_certificate") or "").strip(),
    }


def parse_ca_certificate(pem_text: str) -> dict:
    """Validate a PEM-encoded certificate (or chain - only the first cert is
    inspected for display) and return the metadata the Settings UI shows so
    an admin can confirm they installed the right one before saving.

    Raises ValueError with a human-readable message on anything that isn't
    a parseable X.509 certificate; callers should turn that into a 400.
    """
    text = (pem_text or "").strip()
    if not text:
        raise ValueError("No certificate provided.")
    try:
        cert = x509.load_pem_x509_certificate(text.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Could not parse as a PEM X.509 certificate: {exc}") from exc

    def _name(name: x509.Name) -> str:
        try:
            return name.rfc4514_string()
        except Exception:  # noqa: BLE001
            return str(name)

    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "is_expired": cert.not_valid_after_utc <= datetime.now(timezone.utc),
    }


def public_ldap_config(cfg: dict | None) -> dict:
    """The GET-safe view of the LDAP config: never return the bind
    password (encrypted or not) over the API, only whether one is set."""
    normalized = normalize_ldap_config(cfg)
    public = {k: v for k, v in normalized.items() if k != "bind_password_encrypted"}
    public["bind_password_set"] = bool(normalized.get("bind_password_encrypted"))
    ca_certificate = normalized.get("ca_certificate") or ""
    if ca_certificate:
        try:
            public["ca_certificate_info"] = parse_ca_certificate(ca_certificate)
        except ValueError as exc:
            # Shouldn't happen for anything saved via put_ldap_config (which
            # validates first), but don't let a bad stored value break the
            # settings page from loading.
            public["ca_certificate_info"] = {"error": str(exc)}
    else:
        public["ca_certificate_info"] = None
    return public


async def ldap_authenticate(cfg: dict, username: str, password: str) -> tuple[bool, str, bool]:
    """Try to authenticate `username`/`password` against the directory
    described by `cfg` (already normalize_ldap_config'd).

    Returns (success, detail, is_admin). Runs the blocking ldap3 calls in a
    worker thread so this coroutine never stalls the event loop.
    """

    def _run() -> tuple[bool, str, bool]:
        if not cfg.get("host") or not cfg.get("user_search_base"):
            return False, "LDAP is not fully configured (host/user search base missing).", False

        tls = None
        ca_certificate = (cfg.get("ca_certificate") or "").strip()
        if ca_certificate:
            # Explicit corporate CA installed: require and verify against
            # it. Without this, ldap3's default Tls (no explicit `tls=`
            # passed to Server) does not validate the server certificate at
            # all - so this only ever makes LDAPS/StartTLS *stricter* than
            # the appliance's previous behavior, never looser.
            try:
                tls = ldap3.Tls(
                    ca_certs_data=ca_certificate.encode("utf-8"),
                    validate=ssl.CERT_REQUIRED,
                    version=ssl.PROTOCOL_TLS_CLIENT,
                )
            except Exception as exc:  # noqa: BLE001
                return False, f"Could not load configured corporate CA certificate: {exc}", False

        server = ldap3.Server(cfg["host"], port=cfg["port"], use_ssl=cfg["use_ssl"], get_info=ldap3.NONE, tls=tls)
        bind_password = decrypt_secret(cfg.get("bind_password_encrypted", ""))

        try:
            service_conn = ldap3.Connection(
                server,
                user=cfg.get("bind_dn") or None,
                password=bind_password or None,
                auto_bind=False,
            )
            if cfg.get("start_tls"):
                service_conn.open()
                service_conn.start_tls()
            if not service_conn.bind():
                return False, f"Service-account bind failed: {service_conn.result}", False
        except Exception as exc:  # noqa: BLE001
            return False, f"Could not connect to LDAP host: {exc}", False

        group_attr = cfg.get("group_member_attribute") or "memberOf"
        try:
            search_filter = cfg["user_search_filter"].format(username=escape_filter_chars(username))
        except Exception:  # noqa: BLE001
            search_filter = f"({escape_filter_chars('uid')}={escape_filter_chars(username)})"

        service_conn.search(search_base=cfg["user_search_base"], search_filter=search_filter, attributes=[group_attr])
        if not service_conn.entries:
            service_conn.unbind()
            return False, "No matching user found in the directory.", False

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        member_of: list[str] = []
        try:
            if group_attr in entry:
                member_of = [str(v) for v in entry[group_attr].values]
        except Exception:  # noqa: BLE001
            member_of = []
        service_conn.unbind()

        try:
            user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=False)
            if cfg.get("start_tls"):
                user_conn.open()
                user_conn.start_tls()
            if not user_conn.bind():
                return False, "Invalid username or password.", False
            user_conn.unbind()
        except Exception as exc:  # noqa: BLE001
            return False, f"Bind as user failed: {exc}", False

        admin_group = cfg.get("admin_group_dn")
        is_admin = bool(admin_group) and any(admin_group.lower() == m.lower() for m in member_of)
        return True, "Authenticated.", is_admin

    return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# HTTPS server certificate - Settings -> HTTPS Certificate. Separate from the
# LDAP corporate CA above: that one is a CA the *outbound* LDAPS/StartTLS
# client trusts; this is the leaf certificate + private key nginx and
# uvicorn present *to browsers*. Reads/writes config.TLS_CERT_FILE /
# TLS_KEY_FILE directly - the same two files docker-entrypoint.sh launches
# uvicorn with and the `ui` service's nginx serves from (shared via a Docker
# volume - see docker-compose.yml) - so this page always reflects what's
# actually being served, and neither server picks up a change until it's
# restarted (TLS listeners don't hot-reload a swapped-out cert file).
# ---------------------------------------------------------------------------
def parse_server_certificate(pem_text: str) -> dict:
    """Validate a PEM-encoded leaf certificate (a chain is fine too - only
    the first/leaf cert is inspected here) and return the metadata the
    Settings UI shows. Raises ValueError with a human-readable message on
    anything that isn't a parseable X.509 certificate."""
    text = (pem_text or "").strip()
    if not text:
        raise ValueError("No certificate provided.")
    try:
        cert = x509.load_pem_x509_certificate(text.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Could not parse as a PEM X.509 certificate: {exc}") from exc

    def _name(name: x509.Name) -> str:
        try:
            return name.rfc4514_string()
        except Exception:  # noqa: BLE001
            return str(name)

    san_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = [str(entry.value) for entry in san_ext.value]
    except x509.ExtensionNotFound:
        san_names = []
    except Exception:  # noqa: BLE001
        san_names = []

    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "is_expired": cert.not_valid_after_utc <= datetime.now(timezone.utc),
        "is_self_signed": cert.issuer == cert.subject,
        "subject_alt_names": san_names,
    }


def _public_key_bytes(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def validate_server_key_pair(cert_pem: str, key_pem: str) -> dict:
    """Parse and cross-check a certificate/private-key pair before they're
    ever written to disk. Raises ValueError (400-worthy) for: unparseable
    PEM, a password-protected private key (not supported - neither uvicorn
    nor nginx have a way to be handed a passphrase), or a key that doesn't
    actually match the certificate's public key - the single most common
    mistake when pasting these in by hand."""
    info = parse_server_certificate(cert_pem)

    key_text = (key_pem or "").strip()
    if not key_text:
        raise ValueError("No private key provided.")
    try:
        private_key = serialization.load_pem_private_key(key_text.encode("utf-8"), password=None)
    except TypeError as exc:
        raise ValueError(
            "This private key is password-protected - remove the passphrase before uploading "
            "(uvicorn and nginx have no way to be given one)."
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Could not parse as a PEM private key: {exc}") from exc

    cert = x509.load_pem_x509_certificate(cert_pem.strip().encode("utf-8"))
    if _public_key_bytes(cert.public_key()) != _public_key_bytes(private_key.public_key()):
        raise ValueError("This private key does not match the certificate's public key.")

    return info


def _write_file(path: str, text: str, mode: int) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    os.chmod(path, mode)


def install_server_certificate(cert_pem: str, key_pem: str) -> dict:
    """Validate then install a real HTTPS certificate/key pair, replacing
    the self-signed fallback for both the dashboard and this API. Only
    takes effect after operations-manager and ui are restarted."""
    info = validate_server_key_pair(cert_pem, key_pem)

    # Preserve the original baked-in self-signed cert exactly once, the
    # first time a real certificate is ever installed, so "revert to
    # default" has something to restore instead of just failing.
    if os.path.exists(TLS_CERT_FILE) and not os.path.exists(TLS_CERT_DEFAULT_BACKUP):
        try:
            shutil.copyfile(TLS_CERT_FILE, TLS_CERT_DEFAULT_BACKUP)
            if os.path.exists(TLS_KEY_FILE):
                shutil.copyfile(TLS_KEY_FILE, TLS_KEY_DEFAULT_BACKUP)
                os.chmod(TLS_KEY_DEFAULT_BACKUP, 0o600)
        except OSError as exc:  # noqa: BLE001
            logger.warning("Could not back up the default self-signed certificate: %s", exc)

    _write_file(TLS_CERT_FILE, cert_pem.strip() + "\n", 0o644)
    _write_file(TLS_KEY_FILE, key_pem.strip() + "\n", 0o600)
    logger.info("Installed a new HTTPS server certificate (subject=%s) - restart to apply.", info["subject"])
    return info


def current_server_certificate_info() -> dict | None:
    """Parse whatever certificate is actually on disk right now (never a
    cached copy), so this always reflects the real state after a restart.
    None only if the file is missing or unreadable/unparseable."""
    try:
        with open(TLS_CERT_FILE, "r") as f:
            pem = f.read()
    except OSError:
        return None
    try:
        return parse_server_certificate(pem)
    except ValueError:
        return None


def can_revert_server_certificate() -> bool:
    return os.path.exists(TLS_CERT_DEFAULT_BACKUP) and os.path.exists(TLS_KEY_DEFAULT_BACKUP)


def revert_server_certificate() -> dict:
    """Restore the original baked-in self-signed certificate saved by the
    first install_server_certificate() call. Raises ValueError if no
    custom certificate was ever installed (nothing to revert from)."""
    if not can_revert_server_certificate():
        raise ValueError("No custom certificate has been installed, so there's nothing to revert.")
    shutil.copyfile(TLS_CERT_DEFAULT_BACKUP, TLS_CERT_FILE)
    shutil.copyfile(TLS_KEY_DEFAULT_BACKUP, TLS_KEY_FILE)
    os.chmod(TLS_KEY_FILE, 0o600)
    logger.info("Reverted to the default self-signed HTTPS certificate - restart to apply.")
    info = current_server_certificate_info()
    if info is None:
        raise ValueError("Reverted the certificate files, but the restored default certificate could not be parsed.")
    return info


def new_local_user_doc(
    role: str,
    password_hash: str | None = None,
    source: str = "local",
    must_change_password: bool = False,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "role": role,
        "source": source,
        "password_hash": password_hash,
        "must_change_password": must_change_password,
        "active": True,
        "created_at": now,
        "updated_at": now,
        "last_login_at": None,
    }


def public_user(username: str, doc: dict) -> dict:
    """Strip password_hash before this ever reaches the API layer."""
    return {
        "username": username,
        "role": doc.get("role", DEFAULT_LOCAL_ROLE),
        "source": doc.get("source", "local"),
        "active": bool(doc.get("active", True)),
        "must_change_password": bool(doc.get("must_change_password", False)),
        "has_password": bool(doc.get("password_hash")),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "last_login_at": doc.get("last_login_at"),
    }
