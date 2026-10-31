"""First-run administrator setup (Mf-lyj2): the window, its policy and its race.

The security pin at the centre of this file is the atomic claim. A plain
check-then-insert on SQLite does not fail: two concurrent setups both see "no
administrator", both insert, and the deployment silently ends up with two. That is
why `test_two_concurrent_setups_create_exactly_one_administrator` races five
rounds through the real HTTP surface and `test_a_lost_race_raises_window_closed`
races two raw sessions at the claim itself, where the loser is guaranteed to exist.

Concurrency notes, because they are easy to "optimise" away:

* This module deliberately does **not** install the cheap-argon2 fixture the other
  auth suites use. The real hasher (~50 ms per hash) is what makes the window
  between the winner's write lock and its commit wide enough for the loser to reach
  its own pre-check, so the loser reliably gets the 409 the design promises instead
  of the 404 "window already closed" a much faster winner would produce. The tests
  below hash at most a handful of passwords; the cost is well under a second.
* The throttle records a failure for a lost claim, so the round loop resets
  `login_throttle.first_run_limiter` between rounds. Without that, round five would
  answer 429 before ever reaching the claim, and the test would be asserting the
  throttle, not the race.

Everything else here is the contract from ADR 0009: both routes 404 unless the flag
is on, 409 when the mode leaves no local password sign-in, 422 naming every policy
rule that failed, one audit row that names a sentinel actor, and a password that
reaches neither a log line, a response body nor an audit detail.
"""

import json
import logging
import threading
from typing import Optional
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, delete, select

import accounts
import audit
import auth
import config
import first_run
import login_throttle as login_throttle_module
import main
import sessions
from db import engine
from migrations import run_migrations
from models import AuditEvent, MfaRecoveryCode, OidcIdentity, User, UserSession
from routers import first_run as first_run_routes

URL = "/auth/first-run/setup"
REQUEST_ID_HEADER = "X-Request-ID"
BREAK_GLASS_USERNAME = "admin"
BREAK_GLASS_PASSWORD = "super-secret"
FIRST_ADMIN = "first-admin"
# Twelve-plus characters, no username, not on the blocklist: what the policy wants.
GOOD_PASSWORD = "correct horse battery staple"
ANOTHER_GOOD_PASSWORD = "a much longer passphrase for the second admin"
RULE_IDS = {rule.rule for rule in first_run.PASSWORD_RULES}


def truncate_accounts() -> None:
    """Empty every auth table, children first: the foreign keys are enforced."""
    with Session(engine) as db_session:
        db_session.execute(delete(MfaRecoveryCode))
        db_session.execute(delete(OidcIdentity))
        db_session.execute(delete(UserSession))
        db_session.execute(delete(User))
        db_session.commit()


@pytest.fixture(autouse=True)
def clean_accounts():
    """Migrate once, then start and finish every test without accounts.

    `first_run_limiter.reset()` is in both halves for the same reason
    `tests/test_login_throttle.py` resets `limiter`: one test's 422 must never
    leave a lockout behind for the next one.
    """
    run_migrations(engine)
    truncate_accounts()
    login_throttle_module.limiter.reset()
    login_throttle_module.first_run_limiter.reset()
    yield
    truncate_accounts()
    login_throttle_module.limiter.reset()
    login_throttle_module.first_run_limiter.reset()


@pytest.fixture()
def client():
    with TestClient(main.app) as test_client:
        yield test_client


def enable_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn the opt-in flag on the way a deployment would, at request time."""
    monkeypatch.setattr(auth, "AUTH_FIRST_RUN_SETUP", True)


def set_mode(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> None:
    """Patch the auth mode the way the import does: mode first, then the derived flag.

    The idiom from `tests/test_auth_mode.py`: `AUTH_ENABLED` is computed once at
    import, so a realistic mode change re-derives it with the same expression.
    """
    monkeypatch.setattr(auth, "AUTH_MODE", mode)
    if username is not None:
        monkeypatch.setattr(auth, "AUTH_USERNAME", username)
    if password is not None:
        monkeypatch.setattr(auth, "AUTH_PASSWORD", password)
    monkeypatch.setattr(
        auth,
        "AUTH_ENABLED",
        auth.resolve_auth_enabled(auth.AUTH_MODE, auth.AUTH_USERNAME, auth.AUTH_PASSWORD),
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def setup_body(username: str = FIRST_ADMIN, password: str = GOOD_PASSWORD, confirm: Optional[str] = None) -> dict:
    return {"username": username, "password": password, "confirm_password": password if confirm is None else confirm}


def count_users() -> int:
    with Session(engine) as session:
        return len(list(session.exec(select(User))))


def admin_count() -> int:
    with Session(engine) as session:
        return accounts.count_enabled_admins(session)


def break_glass_login(client: TestClient) -> dict:
    response = client.post("/login", json={"username": BREAK_GLASS_USERNAME, "password": BREAK_GLASS_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def request_id_for(label: str) -> str:
    """A unique, header-legal id: letters, digits and dashes only."""
    return f"{label}-{uuid4().hex}"


def post_setup(client: TestClient, body: Optional[dict] = None, request_id: Optional[str] = None):
    """One setup request, optionally carrying the id its audit row is found by.

    Rows are addressed by request id rather than counted: the audit table is
    append-only and shared for the whole session (`tests/test_audit_log.py` says the
    same), so a bare `SELECT` would also return every other test's row.
    """
    headers = {REQUEST_ID_HEADER: request_id} if request_id else None
    return client.post(URL, json=body or setup_body(), headers=headers)


def first_run_rows(request_id: str) -> list[AuditEvent]:
    """The rows this request wrote; the append-only table is never truncated."""
    with Session(engine) as session:
        statement = select(AuditEvent).where(
            AuditEvent.action == audit.FIRST_RUN_SETUP,
            AuditEvent.request_id == request_id,
        )
        return list(session.exec(statement))


def session_row_count() -> int:
    with Session(engine) as session:
        return len(list(session.exec(select(UserSession))))


def live_break_glass_sessions() -> int:
    with Session(engine) as session:
        rows = session.exec(select(UserSession).where(UserSession.kind == sessions.BREAK_GLASS_KIND)).all()
        return len([row for row in rows if row.revoked_at is None])


# --- the flag is the only thing that exposes the surface --------------------


def test_the_flag_being_off_answers_404_identically_on_both_routes(client) -> None:
    """Off is the default, and off must not even admit the route exists.

    The GET and the POST answer the same frozen string, so a probe cannot tell
    "never configured" from "window already used" and cannot use the difference
    to decide whether to keep trying.
    """
    status = client.get(URL)
    created = client.post(URL, json=setup_body())

    assert status.status_code == 404, status.text
    assert created.status_code == 404, created.text
    assert status.json()["detail"] == created.json()["detail"] == first_run.NOT_AVAILABLE_DETAIL
    assert count_users() == 0


def test_the_open_window_answers_with_the_policy_it_enforces(client, monkeypatch) -> None:
    """The GET is the form's contract: the minimum and every rule id it will use."""
    enable_window(monkeypatch)

    response = client.get(URL)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert body["min_password_length"] == first_run.MIN_PASSWORD_LENGTH == 12
    assert {rule["rule"] for rule in body["rules"]} == RULE_IDS
    assert all(rule["message"] for rule in body["rules"])
    # A cached "available" would leave the form on screen against a shut window.
    assert response.headers["Cache-Control"] == "no-store"


# --- the setup itself -------------------------------------------------------


def test_setup_creates_an_administrator_and_signs_them_in(client, monkeypatch) -> None:
    """201 with the same token pair `/login` returns, and the notice that closes the loop."""
    enable_window(monkeypatch)

    response = client.post(URL, json=setup_body())

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["token"]
    assert body["refresh_token"]
    assert body["expires_in"] == auth.AUTH_ACCESS_TOKEN_TTL
    assert body["notice"] == first_run_routes.NOTICE
    assert "AUTH_FIRST_RUN_SETUP" in body["notice"]
    assert "AUTH_PASSWORD" in body["notice"]
    assert response.headers["Cache-Control"] == "no-store"

    me = client.get("/me", headers=bearer(body["token"]))
    assert me.status_code == 200, me.text
    assert me.json()["username"] == FIRST_ADMIN
    assert me.json()["role"] == accounts.ADMIN_ROLE
    assert me.json()["kind"] == sessions.PASSWORD_KIND

    with Session(engine) as session:
        user = accounts.get_user_by_username(session, FIRST_ADMIN)
        assert user is not None
        assert user.role == accounts.ADMIN_ROLE
        assert not user.disabled
        assert user.password_hash and user.password_hash != GOOD_PASSWORD
        session_row = session.exec(select(UserSession).where(UserSession.user_id == user.id)).first()
        # A fresh account has no seed, so no second factor can be skipped, and the
        # session it was handed has not proved one either: an admin MFA policy
        # enabled later demands enrolment before admin routes, and `/mfa/enrol` is
        # READ, so there is no dead end (ADR 0009).
        assert user.totp_secret is None
        assert not auth.mfa_required(user)
        assert session_row is not None
        assert session_row.mfa_verified_at is None


def test_the_window_closes_itself_once_an_administrator_exists(client, monkeypatch) -> None:
    """The first enabled admin is the threshold, flag or no flag."""
    enable_window(monkeypatch)
    assert client.post(URL, json=setup_body()).status_code == 201

    assert client.get(URL).status_code == 404
    second = client.post(URL, json=setup_body(username="second-admin", password=ANOTHER_GOOD_PASSWORD))

    assert second.status_code == 404
    assert second.json()["detail"] == first_run.NOT_AVAILABLE_DETAIL
    assert admin_count() == 1


# --- the refusals -----------------------------------------------------------


def test_auth_disabled_answers_409_naming_the_mode(client, monkeypatch) -> None:
    """There is no sign-in to protect when authentication is off."""
    enable_window(monkeypatch)
    set_mode(monkeypatch, auth.AUTH_MODE_OFF)

    response = client.post(URL, json=setup_body())

    assert response.status_code == 409, response.text
    assert "AUTH_MODE=off" in response.json()["detail"]
    assert count_users() == 0


def test_oidc_mode_answers_409_and_names_the_way_out(client, monkeypatch) -> None:
    """`oidc` cannot bootstrap an admin - SSO is refused one - so this is a dead end.

    It has to say which mode works instead, because the alternative reading of a 409
    here is "type your password again", which would never succeed.
    """
    enable_window(monkeypatch)
    set_mode(monkeypatch, auth.AUTH_MODE_OIDC)

    response = client.post(URL, json=setup_body())

    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert "AUTH_MODE=oidc" in detail
    assert "AUTH_MODE=both" in detail
    assert count_users() == 0


def test_each_policy_rule_is_a_422_naming_its_id(client, monkeypatch) -> None:
    """One request per rule, each violating exactly that rule and naming its id.

    The expected id is written out next to each case rather than re-derived from
    `check_password`: the point is that a human decided this case means this rule.
    Each timestamp-free case is also a fresh window, because a successful setup
    would close it.
    """
    cases = [
        ("min_length", setup_body(password="short", confirm="short")),
        ("max_length", setup_body(password="a" * (accounts.MAX_PASSWORD_LENGTH + 1))),
        ("contains_username", setup_body(username="alice", password="alicealicealice")),
        ("blocklisted", setup_body(password="PasswordPassword")),
        ("confirm_mismatch", setup_body(password=GOOD_PASSWORD, confirm="a different passphrase")),
    ]
    enable_window(monkeypatch)

    for expected, body in cases:
        login_throttle_module.first_run_limiter.reset()
        response = client.post(URL, json=body)

        assert response.status_code == 422, (expected, response.text)
        detail = response.json()["detail"]
        assert detail["message"] == "password does not meet the policy"
        assert [violation["rule"] for violation in detail["rules"]] == [expected]
        assert detail["rules"][0]["message"]
        assert count_users() == 0


def test_every_violation_is_reported_at_once(client, monkeypatch) -> None:
    """Told once, not once per attempt: all five rules, in the canonical order."""
    enable_window(monkeypatch)

    response = client.post(URL, json={"username": "admin", "password": "admin", "confirm_password": "nope"})

    assert response.status_code == 422, response.text
    reported = [violation["rule"] for violation in response.json()["detail"]["rules"]]
    assert reported == ["min_length", "contains_username", "blocklisted", "confirm_mismatch"]
    assert count_users() == 0


def test_a_fullwidth_spelling_of_a_blocklisted_word_is_still_refused(client, monkeypatch) -> None:
    """The blocklist folds compatibility forms, so a keyboard layout is not a bypass.

    `ｐａｓｓｗｏｒｄｐａｓｓｗｏｒｄ` is sixteen characters, contains no username and
    starts with the very term the blocklist names; without NFKC folding it is a
    password an impatient operator - the one this rule exists for - types by
    accident on a Japanese or Chinese input method.
    """
    enable_window(monkeypatch)

    response = client.post(URL, json=setup_body(password="ｐａｓｓｗｏｒｄｐａｓｓｗｏｒｄ"))

    assert response.status_code == 422, response.text
    assert [violation["rule"] for violation in response.json()["detail"]["rules"]] == ["blocklisted"]
    assert count_users() == 0


# --- nothing secret leaves the request body ---------------------------------


def test_the_password_reaches_no_log_line_body_or_audit_row(client, monkeypatch, caplog) -> None:
    """The one value that must never be observable outside the form.

    Asserted on all three surfaces an operator can actually read: the log (captured
    at DEBUG, so a debug print would be caught), the response body, and the audit
    row's target and detail. The rejected path is checked too, because the 422
    reports rules and a careless implementation would echo the value it refused.
    """
    enable_window(monkeypatch)
    caplog.set_level(logging.DEBUG)
    # A password that satisfies the policy but is unique enough that a hit is real.
    secret = "unique-canary-passphrase-9f2c"
    request_id = request_id_for("canary")

    rejected = post_setup(client, setup_body(password=secret, confirm="mismatch-canary-passphrase"), request_id)
    accepted = post_setup(client, setup_body(password=secret), request_id)

    assert rejected.status_code == 422
    assert accepted.status_code == 201
    for response in (rejected, accepted):
        assert secret not in response.text
    assert secret not in caplog.text

    rows = first_run_rows(request_id)
    assert len(rows) == 1
    assert secret not in (rows[0].detail_json or "")
    assert secret not in (rows[0].target or "")
    assert secret not in rows[0].actor


# --- throttling -------------------------------------------------------------


def test_repeated_policy_failures_throttle_the_one_bucket(client, monkeypatch) -> None:
    """The bucket is fixed, so the key space cannot multiply the argon2 budget.

    Three failures then a 429 with `Retry-After`, exactly like `/login`, and the
    limit is monkeypatched so the test does not wait out a real lockout.
    """
    enable_window(monkeypatch)
    monkeypatch.setattr(config, "LOGIN_THROTTLE_ENABLED", True)
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 2)
    monkeypatch.setattr(config, "LOGIN_FAILURE_WINDOW_SECONDS", 900)
    monkeypatch.setattr(config, "LOGIN_LOCKOUT_SECONDS", 300)
    monkeypatch.setattr(config, "LOGIN_MAX_LOCKOUT_SECONDS", 3600)
    login_throttle_module.first_run_limiter.reset()

    for _ in range(2):
        assert client.post(URL, json=setup_body(password="short", confirm="short")).status_code == 422

    locked = client.post(URL, json=setup_body())

    assert locked.status_code == 429, locked.text
    assert locked.headers["Retry-After"].isdigit()
    assert int(locked.headers["Retry-After"]) >= 1
    assert count_users() == 0


def test_a_closed_window_does_not_record_a_throttle_failure(client, monkeypatch) -> None:
    """A 404 is a refusal, not a failed attempt: it must never lock the live window."""
    enable_window(monkeypatch)
    monkeypatch.setattr(config, "LOGIN_THROTTLE_ENABLED", True)
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 1)
    login_throttle_module.first_run_limiter.reset()
    assert client.post(URL, json=setup_body()).status_code == 201

    for _ in range(3):
        assert client.post(URL, json=setup_body(username="other")).status_code == 404

    assert login_throttle_module.first_run_limiter.retry_after(first_run.FIRST_RUN_THROTTLE_KEY) == 0


# --- break-glass and the audit row -----------------------------------------


def test_setup_revokes_the_break_glass_sessions(client, monkeypatch) -> None:
    """The env admin's door shuts with the account that made it obsolete.

    The old token has to die in the same transaction: a break-glass session that
    outlived the account would be an admin credential nobody can attribute.
    """
    enable_window(monkeypatch)
    glass = break_glass_login(client)
    assert client.get("/me", headers=bearer(glass["token"])).status_code == 200

    assert client.post(URL, json=setup_body()).status_code == 201

    assert client.get("/me", headers=bearer(glass["token"])).status_code == 401
    assert live_break_glass_sessions() == 0
    assert client.post("/login", json={"username": BREAK_GLASS_USERNAME, "password": BREAK_GLASS_PASSWORD}).status_code == 401


def test_one_audit_row_names_a_sentinel_actor_and_no_secret(client, monkeypatch) -> None:
    """One row, one fact: the sentinel actor, the chosen username, the count it shut."""
    enable_window(monkeypatch)
    break_glass_login(client)
    request_id = request_id_for("sentinel")

    assert post_setup(client, request_id=request_id).status_code == 201

    rows = first_run_rows(request_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.action == audit.FIRST_RUN_SETUP
    assert row.actor == audit.ACTOR_FIRST_RUN
    assert row.actor_kind == audit.ACTOR_FIRST_RUN_KIND
    assert row.actor_role == audit.ACTOR_FIRST_RUN_ROLE
    assert row.actor_user_id is None
    assert row.target == FIRST_ADMIN
    detail = json.loads(row.detail_json or "{}")
    assert detail["username"] == FIRST_ADMIN
    assert detail["role"] == accounts.ADMIN_ROLE
    assert detail["source"] == "first_run_setup"
    assert detail["flag"] == "AUTH_FIRST_RUN_SETUP"
    assert detail["break_glass_sessions_revoked"] == 1
    assert detail["user_id"]
    assert "password" not in json.dumps(detail)


# --- the race ---------------------------------------------------------------


def test_two_concurrent_setups_create_exactly_one_administrator(client, monkeypatch) -> None:
    """Five rounds of two simultaneous POSTs: one 201, one 409, one admin.

    This is the test the `BEGIN IMMEDIATE` claim exists for. Against a plain
    check-then-insert both requests succeed (SQLite serialises the writes, not the
    reads), the round yields two 201s, and the deployment ends up with two
    administrators while the operator believes they made one.

    The limiter is reset between rounds because a lost claim records a failure;
    without it round five would answer 429 before reaching the claim.
    """
    enable_window(monkeypatch)
    rounds = 5
    for round_number in range(rounds):
        truncate_accounts()
        login_throttle_module.first_run_limiter.reset()
        username = f"racer-{round_number}"

        statuses = race_setups(client, username)

        assert sorted(statuses) == [201, 409], f"round {round_number} answered {statuses}"
        assert admin_count() == 1, f"round {round_number} left {admin_count()} enabled administrators"

    assert admin_count() == 1


def race_setups(client: TestClient, username: str) -> list[int]:
    """Fire two identical setups at once and return both status codes.

    A `threading.Barrier` releases both threads together, so neither can win by
    starting first. Both requests go through the same `TestClient`, whose portal
    drives the ASGI app on one event loop while the synchronous handlers run on
    separate worker threads - i.e. real concurrency against one database file.
    """
    barrier = threading.Barrier(2)
    statuses: list[int] = []
    lock = threading.Lock()
    body = setup_body(username=username, password=GOOD_PASSWORD)

    def worker() -> None:
        barrier.wait(timeout=10)
        response = client.post(URL, json=body)
        with lock:
            statuses.append(response.status_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return statuses


def test_a_lost_race_raises_window_closed_and_writes_no_second_row() -> None:
    """The claim itself, with two sessions and one barrier: loser raises, one row remains.

    Deliberately below the HTTP layer, so the assertion is about
    `first_run.claim_first_admin` rather than about what a status code implies.
    Both threads are inside `BEGIN IMMEDIATE` before either can commit, so the
    loser is guaranteed to exist and to be refused.
    """
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker(username: str) -> None:
        with Session(engine) as session:
            barrier.wait(timeout=10)
            try:
                first_run.claim_first_admin(session, username, GOOD_PASSWORD)
                session.commit()
                outcome = "created"
            except first_run.WindowClosed:
                outcome = "window closed"
            except Exception as exc:  # noqa: BLE001 - the assertion reports anything else
                outcome = f"unexpected {type(exc).__name__}: {exc}"
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("race-a", "race-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert sorted(outcomes) == ["created", "window closed"], outcomes
    assert admin_count() == 1
    assert count_users() == 1


def test_a_duplicate_username_leaves_no_partial_write_and_keeps_the_glass_door(client, monkeypatch) -> None:
    """`accounts.create_user` rolls back on a duplicate, and that rollback ends the claim.

    So the handler must do nothing else with the session on that path. Anything
    staged afterwards would commit with no administrator in it - and a
    `revoke_break_glass` staged there would shut the only door while zero admins
    exist, which is the lockout `accounts.LastAdmin` warns about and which nothing in
    the API can undo.

    The pre-existing row is seeded through `accounts.create_user` rather than
    `POST /users` on purpose: the route revokes every break-glass session as part of
    closing the door, and this test needs a live break-glass session to prove the
    failing setup did not shut one. A viewer also keeps the setup window open, whose
    threshold is the *enabled admin* count, not the users table.
    """
    enable_window(monkeypatch)
    glass = break_glass_login(client)
    with Session(engine) as session:
        accounts.create_user(session, "taken", GOOD_PASSWORD, role=accounts.DEFAULT_ROLE)
        session.commit()
    assert client.get("/me", headers=bearer(glass["token"])).status_code == 200
    sessions_before = session_row_count()
    request_id = request_id_for("duplicate")

    response = post_setup(client, setup_body(username="taken", password=ANOTHER_GOOD_PASSWORD), request_id)

    assert response.status_code == 409, response.text
    assert admin_count() == 0
    assert count_users() == 1
    assert first_run_rows(request_id) == []
    assert session_row_count() == sessions_before
    assert client.get("/me", headers=bearer(glass["token"])).status_code == 200
    assert live_break_glass_sessions() == 1


# --- the boot line ----------------------------------------------------------


def test_the_startup_notice_says_open_closed_and_why_not(client, monkeypatch) -> None:
    """The line an operator reads at boot is the same decision the routes make."""
    enable_window(monkeypatch)
    with Session(engine) as session:
        assert first_run.startup_notice(session) == first_run.STARTUP_OPEN_NOTICE
        assert "open" in first_run.STARTUP_OPEN_NOTICE
        assert "AUTH_FIRST_RUN_SETUP" in first_run.STARTUP_OPEN_NOTICE

    assert client.post(URL, json=setup_body()).status_code == 201

    with Session(engine) as session:
        closed = first_run.startup_notice(session)
    assert closed.startswith("First-run setup window: closed (1 enabled administrator(s) exist")
    assert "unset `AUTH_FIRST_RUN_SETUP`" in closed

    set_mode(monkeypatch, auth.AUTH_MODE_OFF)
    with Session(engine) as session:
        refused = first_run.startup_notice(session)
    assert refused.startswith("First-run setup window: unavailable (authentication is disabled")
    assert "AUTH_MODE=off" in refused


def test_the_startup_notice_is_quiet_when_the_flag_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """`main` only logs when the flag is on; the helper still answers honestly."""
    monkeypatch.setattr(auth, "AUTH_FIRST_RUN_SETUP", False)
    with Session(engine) as session:
        notice = first_run.startup_notice(session)
    assert notice.startswith("First-run setup window: unavailable")
    assert first_run.NOT_AVAILABLE_DETAIL in notice
