"""First-run administrator setup: the one window a fresh deployment has (Mf-lyj2).

Every way into a fresh Curiarium needed something set up before it could be used.
Break-glass needs an `AUTH_USERNAME`/`AUTH_PASSWORD` pair the operator invents
before they have seen the UI; SSO refuses to provision the first administrator
(`oidc.NoAdminBootstrap`), because a claim may never mint an admin; and
`POST /users` needs a session, which needs an admin. The result was a deployment
that could only be opened by editing `.env` and restarting. This module is the
third door: a short-lived, deliberately opened window that mints the first
administrator from the browser, and then closes itself for good.

The window is *state*, not a flag. `AUTH_FIRST_RUN_SETUP` opens the possibility,
but the window itself is open exactly while no enabled administrator exists, and
the first enabled admin closes it whether or not the flag is still set. That is
the point: forgetting to unset the flag on the internet costs nothing once the row
exists, and the boot log says so (`startup_notice`).

Two details here are load-bearing and easy to "simplify" into a security bug:

* **The claim is one `BEGIN IMMEDIATE`, before the count read** (`claim_first_admin`).
  A plain check-then-insert does not error on SQLite - both requests succeed and
  the deployment silently gains two administrators, so the deployment's own
  operator cannot tell it raced. Taking the write lock first makes the loser wait
  at `BEGIN`, read the winner's committed row and refuse.
* **`accounts.create_user` rolls the transaction back on a duplicate**
  (`session.rollback()`, accounts.py), which ends our claimed transaction. The
  caller must therefore do nothing else with that session on the `AccountError`
  path: staging an audit row or revoking the break-glass sessions afterwards would
  commit on a session with no administrator in it, revoking every break-glass door
  while zero admins exist - the unrecoverable lockout `accounts.LastAdmin` exists
  to prevent.

Nothing here re-implements password hashing, the admin count or session minting:
`accounts.hash_password`, `accounts.count_enabled_admins`, `sessions.create` and
`auth.create_access_token` are the only implementations this repo has, and a
second one is a second chance to get it wrong.

The password policy is deliberately stricter than `accounts.MIN_PASSWORD_LENGTH`
(8, used by `/users` and the admin reset): this is the one account nobody can
recover, chosen once at a keyboard on a fresh install, so it gets the NIST
SP 800-63B floor for a single factor - 12 characters, which still fits a
passphrase. ADR 0009 owns that divergence.
"""

import logging
import unicodedata
from dataclasses import dataclass
from typing import Optional

from sqlmodel import Session

import accounts
import auth
from models import User

log = logging.getLogger(__name__)

# One fixed throttle key for the whole window, never the submitted username. The
# username space is attacker-controlled and unauthenticated here, so a
# per-username bucket would multiply the argon2 budget up to
# `login_throttle.MAX_BUCKETS` (1024) hashes per lockout window on a route that
# exists before any credential does. One bucket means the DoS is "you locked the
# one-time setup", whose recovery is a restart, and an attacker who can do that
# could instead simply claim the administrator - strictly worse for them.
FIRST_RUN_THROTTLE_KEY = "first-run"

# 12, not accounts.MIN_PASSWORD_LENGTH (8): see the module docstring.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = accounts.MAX_PASSWORD_LENGTH

# One frozen string for both routes and both closed reasons (flag off, admin
# exists), so the surface advertises nothing about which state it is in.
NOT_AVAILABLE_DETAIL = "first-run setup is not available"

STARTUP_OPEN_NOTICE = "First-run setup window: open (no enabled administrator; `AUTH_FIRST_RUN_SETUP`=1)"

# Compared lowercase and alphanumeric-only, and by prefix rather than equality
# only: `Passw0rd!`, `p-a-s-s-w-o-r-d` and `password123!` are the same mistake,
# and an equality test misses the last two. Short enough to read, long enough to
# catch the passwords an operator types when they are impatient with a fresh box.
BLOCKLIST = (
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "changeme",
    "admin",
    "administrator",
    "welcome",
    "iloveyou",
    "abc123",
    "monkey",
    "dragon",
    "curiarium",
    "makersvault",
    "vault",
    "firstrun",
    "printer",
    "3dprint",
    "secret",
)


@dataclass(frozen=True)
class Rule:
    """One password rule, with the message both the 422 and the form display."""

    rule: str
    message: str


@dataclass(frozen=True)
class Refusal:
    """Why the setup window is not open, as the HTTP status and detail to send."""

    status_code: int
    detail: str


# One canonical copy of each message, in evaluation order: `GET` hands the form
# this exact list and a 422 reports the same objects, so the client's advice and
# the server's demand cannot drift apart.
PASSWORD_RULES: tuple[Rule, ...] = (
    Rule("min_length", f"password must be at least {MIN_PASSWORD_LENGTH} characters"),
    Rule("max_length", f"password must be at most {MAX_PASSWORD_LENGTH} characters"),
    Rule("contains_username", "password must not contain the username"),
    Rule("blocklisted", "password must not be a common or predictable password"),
    Rule("confirm_mismatch", "the two passwords do not match"),
)


class WindowClosed(Exception):
    """The setup window closed between the pre-check and the claim.

    A different fact from the pre-check's 404, so it gets a different answer (409):
    the caller watched the window open, another caller took it, and retrying can
    only fail.
    """


def _blocklisted(password: str) -> bool:
    """True when the password is, or begins with, a known-weak term.

    NFKC-folded before the alphanumeric strip, so a fullwidth or compatibility
    spelling (`ｐａｓｓｗｏｒｄ`) is the same mistake as the ASCII one. Without that
    fold the blocklist is a check an impatient operator walks around with a
    keyboard layout, which is exactly the operator it exists for.
    """
    folded = unicodedata.normalize("NFKC", password or "")
    compact = "".join(character for character in folded.lower() if character.isalnum())
    if not compact:
        return False
    return any(compact.startswith(term) for term in BLOCKLIST)


def check_password(username: str, password: str, confirm_password: str) -> list[Rule]:
    """Every rule this password violates, all of them, in canonical order.

    Collecting rather than raising on the first failure is deliberate: an operator
    typing a long passphrase should be told everything wrong with it once, not once
    per attempt. The password itself is never returned, logged or stored here.
    """
    username_key = (username or "").strip().casefold()
    violated = {
        "min_length": len(password or "") < MIN_PASSWORD_LENGTH,
        "max_length": len(password or "") > MAX_PASSWORD_LENGTH,
        "contains_username": bool(username_key) and username_key in (password or "").casefold(),
        "blocklisted": _blocklisted(password),
        "confirm_mismatch": (confirm_password or "") != (password or ""),
    }
    return [rule for rule in PASSWORD_RULES if violated[rule.rule]]


def setup_refusal(session: Session) -> Optional[Refusal]:
    """Why both setup routes must refuse right now, or None while the window is open.

    Order is the contract, and it is shared by GET and POST so the two routes can
    never disagree about whether the window is open:

    1. flag off -> 404, before anything else, so a deployment that never opted in
       does not so much as admit the route exists;
    2. auth disabled -> 409: there is no sign-in for an administrator to protect;
    3. `AUTH_MODE=oidc` -> 409: that mode refuses local password sign-in, and SSO
       cannot mint the first admin, so the window is a genuine dead end and has to
       say which knob to turn instead;
    4. an enabled administrator exists -> 404, the window having closed itself.

    2 and 3 are 409 rather than the codebase's 503 idiom: `DISABLED_503_KEYS` is a
    two-sided pin over the auth endpoints that refuse *while authentication is
    off*, and these two are refusals of a deliberately opened window, not that.
    ADR 0009 records the reasoning.
    """
    if not auth.AUTH_FIRST_RUN_SETUP:
        return Refusal(404, NOT_AVAILABLE_DETAIL)
    if not auth.AUTH_ENABLED:
        return Refusal(
            409,
            f"authentication is disabled (`AUTH_MODE={auth.AUTH_MODE}`), so there is no sign-in for an administrator to protect",
        )
    if not auth.password_login_allowed():
        return Refusal(
            409,
            f"`AUTH_MODE={auth.AUTH_MODE}` refuses local password sign-in; set `AUTH_MODE=both` (or `local`) "
            "to create the first administrator locally",
        )
    if accounts.count_enabled_admins(session) != 0:
        return Refusal(404, NOT_AVAILABLE_DETAIL)
    return None


def begin_write_transaction(session: Session) -> None:
    """Take SQLite's write lock before the window read, or refuse to race.

    `BEGIN IMMEDIATE` is the whole mechanism: it acquires the write lock up front,
    so a second claim blocks here (WAL plus `busy_timeout=10000`, db.py) instead of
    reading "no admins yet" alongside us and inserting a second administrator.

    It only works as the *first write on the session*. The router may run SELECTs
    before it - the refusal pre-check does - because pysqlite's legacy transaction
    mode leaves `in_transaction` False after a read, but any DML would have already
    opened a transaction and SQLite answers `cannot start a transaction within a
    transaction`. The explicit guard names that contract instead of letting a
    driver change surface as a bare OperationalError, and it is what makes a future
    "just log the attempt first" refactor fail loudly rather than race silently.
    """
    connection = session.connection()
    dbapi = connection.connection.dbapi_connection
    if dbapi.in_transaction:
        raise RuntimeError("first-run claim must be the first write on its session")
    connection.exec_driver_sql("BEGIN IMMEDIATE")


def claim_first_admin(session: Session, username: str, password: str) -> User:
    """Create the first administrator, atomically, or raise `WindowClosed`.

    Raises `accounts.DuplicateAccount` (409) when the username is taken and
    `accounts.InvalidAccount` (422) when `create_user` refuses the input; both are
    `accounts.AccountError` and both have already rolled this session back, so the
    caller must not write anything else through it afterwards (see the module
    docstring).
    """
    begin_write_transaction(session)
    if accounts.count_enabled_admins(session) != 0:
        raise WindowClosed("an enabled administrator already exists")
    return accounts.create_user(session, username, password, role=accounts.ADMIN_ROLE)


def startup_notice(session: Session) -> str:
    """One operator-facing line describing the window, for the boot log.

    Deliberately a re-derivation of `setup_refusal` rather than a second opinion:
    the line an operator reads at boot is the same decision the routes make. The
    closed case is spelled out with the count because "unset the flag" is only
    correct advice once an administrator actually exists.
    """
    refusal = setup_refusal(session)
    if refusal is None:
        return STARTUP_OPEN_NOTICE
    if refusal.status_code == 404 and auth.AUTH_FIRST_RUN_SETUP:
        admins = accounts.count_enabled_admins(session)
        return f"First-run setup window: closed ({admins} enabled administrator(s) exist; unset `AUTH_FIRST_RUN_SETUP`)"
    return f"First-run setup window: unavailable ({refusal.detail})"
