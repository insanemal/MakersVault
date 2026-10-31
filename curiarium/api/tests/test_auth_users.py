"""Accounts, revocable sessions and the auth endpoints added by Mf-vuy1.

Every test starts from an empty users/sessions pair and the shared login
throttle cleared, so nothing here can leak a user or a lockout into the smoke
test's break-glass login.
"""

import time

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, delete, select

import auth
import config
import login_throttle as login_throttle_module
import main
import sessions
from db import engine
from migrations import run_migrations
from models import AuditEvent, MfaRecoveryCode, OidcIdentity, Project, User, UserSession

ADMIN_USERNAME = "root"
ADMIN_PASSWORD = "root-password-1"
VIEWER_PASSWORD = "viewer-password-1"


def truncate_accounts() -> None:
    with Session(engine) as db:
        # Children first, like the API's own delete path: the foreign keys are
        # enforced, so a recovery-code row would otherwise keep its account alive.
        db.execute(delete(MfaRecoveryCode))
        db.execute(delete(OidcIdentity))
        db.execute(delete(UserSession))
        db.execute(delete(User))
        db.commit()


@pytest.fixture(autouse=True)
def clean_accounts():
    """Migrate once, then start and finish every test without accounts."""
    run_migrations(engine)
    truncate_accounts()
    login_throttle_module.limiter.reset()
    yield
    truncate_accounts()
    login_throttle_module.limiter.reset()


@pytest.fixture()
def client():
    with TestClient(main.app) as test_client:
        yield test_client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def break_glass_login(client: TestClient) -> dict:
    response = client.post("/login", json={"username": "admin", "password": "super-secret"})
    assert response.status_code == 200, response.text
    return response.json()


def login_user(client: TestClient, username: str, password: str) -> dict:
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def create_user(
    client: TestClient,
    admin_token: str,
    username: str,
    password: str,
    role: str = "viewer",
    email: str | None = None,
) -> dict:
    payload: dict = {"username": username, "password": password, "role": role}
    if email is not None:
        payload["email"] = email
    response = client.post("/users", json=payload, headers=bearer(admin_token))
    assert response.status_code == 201, response.text
    return response.json()


def bootstrap_admin(client: TestClient) -> dict:
    """Let break-glass create the first (admin) account, then sign in as it."""
    glass = break_glass_login(client)
    create_user(client, glass["token"], ADMIN_USERNAME, ADMIN_PASSWORD, role="admin")
    return login_user(client, ADMIN_USERNAME, ADMIN_PASSWORD)


def session_row(refresh_token: str) -> UserSession:
    with Session(engine) as db:
        row = sessions.find_by_refresh_hash(db, sessions.hash_refresh_token(refresh_token))
        assert row is not None, "the refresh token has no session row"
        db.expunge(row)
    return row


def test_break_glass_login_opens_an_admin_session(client: TestClient) -> None:
    tokens = break_glass_login(client)

    assert tokens["expires_in"] == 900
    assert tokens["token_type"] == "bearer"
    assert tokens["refresh_token"]

    me = client.get("/me", headers=bearer(tokens["token"]))
    assert me.status_code == 200
    assert me.json() == {
        "id": None,
        "username": "admin",
        "email": None,
        "role": "admin",
        "disabled": False,
        "kind": "break-glass",
    }
    assert client.get("/assets", headers=bearer(tokens["token"])).status_code == 200

    row = session_row(tokens["refresh_token"])
    assert row.kind == "break-glass"
    assert row.user_id is None
    assert row.username == "admin"


def test_creating_the_first_user_revokes_break_glass_sessions(client: TestClient) -> None:
    glass = break_glass_login(client)
    create_user(client, glass["token"], ADMIN_USERNAME, ADMIN_PASSWORD, role="admin")

    assert client.get("/assets", headers=bearer(glass["token"])).status_code == 401
    assert client.post("/refresh", json={"refresh_token": glass["refresh_token"]}).status_code == 401


def test_break_glass_stops_working_once_a_user_exists(client: TestClient) -> None:
    glass = break_glass_login(client)
    create_user(client, glass["token"], ADMIN_USERNAME, ADMIN_PASSWORD, role="admin")

    response = client.post("/login", json={"username": "admin", "password": "super-secret"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_rejected_break_glass_still_feeds_the_login_throttle(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    glass = break_glass_login(client)
    create_user(client, glass["token"], ADMIN_USERNAME, ADMIN_PASSWORD, role="admin")
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 1)

    first = client.post("/login", json={"username": "admin", "password": "super-secret"})
    second = client.post("/login", json={"username": "admin", "password": "super-secret"})

    assert first.status_code == 401
    assert first.json()["detail"] == "Invalid username or password"
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) > 0


def test_admin_creates_a_user_without_leaking_the_hash(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD, email="alice@example.com")

    assert created["username"] == "alice"
    assert created["role"] == "viewer"
    assert created["disabled"] is False
    assert created["email"] == "alice@example.com"
    assert "password_hash" not in created

    listing = client.get("/users", headers=bearer(tokens["token"]))
    assert listing.status_code == 200
    assert [user["username"] for user in listing.json()] == ["alice", "root"]
    assert all("password_hash" not in user for user in listing.json())

    with Session(engine) as db:
        stored = db.get(User, created["id"]).password_hash or ""
    with engine.connect() as conn:
        stored_rows = str(conn.exec_driver_sql("SELECT * FROM users").fetchall())
    assert stored.startswith("$argon2id$")
    assert VIEWER_PASSWORD not in stored_rows


def test_created_user_can_log_in_and_see_itself(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD, email="alice@example.com")

    alice = login_user(client, "alice", VIEWER_PASSWORD)

    me = client.get("/me", headers=bearer(alice["token"]))
    assert me.status_code == 200
    assert me.json() == {
        "id": created["id"],
        "username": "alice",
        "email": "alice@example.com",
        "role": "viewer",
        "disabled": False,
        "kind": "password",
    }
    assert client.get("/assets", headers=bearer(alice["token"])).status_code == 200


def test_refresh_rotates_and_the_old_token_gets_one_grace(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    original = tokens["refresh_token"]

    refreshed = client.post("/refresh", json={"refresh_token": original})

    assert refreshed.status_code == 200, refreshed.text
    rotated = refreshed.json()
    assert rotated["refresh_token"] and rotated["refresh_token"] != original
    assert rotated["expires_in"] == 900
    assert client.get("/assets", headers=bearer(rotated["token"])).status_code == 200

    # Inside the grace window the superseded token is interchangeable ONCE:
    # that is what lets two tabs sharing one browser session survive a race.
    graced = client.post("/refresh", json={"refresh_token": original})
    assert graced.status_code == 200, graced.text
    assert graced.json()["refresh_token"] not in {original, rotated["refresh_token"]}

    # The grace consumed the one generation of history this row keeps, so the
    # same original is now a hash older than that and is a plain 401.
    assert client.post("/refresh", json={"refresh_token": original}).status_code == 401

    # The token minted by the first rotation is still accepted: only the
    # replayed generation was superseded, and the session stayed live.
    assert client.post("/refresh", json={"refresh_token": rotated["refresh_token"]}).status_code == 200


def test_logout_revokes_access_and_refresh(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    assert client.post("/logout", json={"refresh_token": tokens["refresh_token"]}).status_code == 204

    assert client.get("/assets", headers=bearer(tokens["token"])).status_code == 401
    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    # logout is idempotent, including for a token that is already dead
    assert client.post("/logout", json={"refresh_token": tokens["refresh_token"]}).status_code == 204
    assert client.post("/logout", json={"refresh_token": "never-existed"}).status_code == 204


def test_revoked_session_cannot_mint_tokens(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    with Session(engine) as db:
        row = sessions.find_by_refresh_hash(db, sessions.hash_refresh_token(tokens["refresh_token"]))
        sessions.revoke(db, row)
        db.commit()

    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/assets", headers=bearer(tokens["token"])).status_code == 401


def test_access_token_is_not_a_refresh_token(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    response = client.post("/refresh", json={"refresh_token": tokens["token"]})

    assert response.status_code == 401


def test_unknown_garbage_and_expired_refresh_tokens_are_rejected(client: TestClient) -> None:
    assert client.post("/refresh", json={"refresh_token": "not-a-token"}).status_code == 401
    assert client.post("/refresh", json={"refresh_token": ""}).status_code == 401

    tokens = bootstrap_admin(client)
    with Session(engine) as db:
        row = sessions.find_by_refresh_hash(db, sessions.hash_refresh_token(tokens["refresh_token"]))
        row.refresh_expires_at = int(time.time()) - 1
        db.add(row)
        db.commit()

    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_disabled_user_loses_every_session_and_cannot_log_in(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    alice = login_user(client, "alice", VIEWER_PASSWORD)

    patched = client.patch(f"/users/{created['id']}", json={"disabled": True}, headers=bearer(tokens["token"]))

    assert patched.status_code == 200
    assert patched.json()["disabled"] is True
    assert client.get("/assets", headers=bearer(alice["token"])).status_code == 401
    assert client.post("/refresh", json={"refresh_token": alice["refresh_token"]}).status_code == 401
    assert client.post("/login", json={"username": "alice", "password": VIEWER_PASSWORD}).status_code == 401

    enabled = client.patch(f"/users/{created['id']}", json={"disabled": False}, headers=bearer(tokens["token"]))
    assert enabled.status_code == 200
    assert login_user(client, "alice", VIEWER_PASSWORD)["token"]


def test_disabled_login_is_indistinguishable_from_a_wrong_password(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    client.patch(f"/users/{created['id']}", json={"disabled": True}, headers=bearer(tokens["token"]))

    wrong_password = client.post("/login", json={"username": "alice", "password": "not-the-password"})
    disabled = client.post("/login", json={"username": "alice", "password": VIEWER_PASSWORD})

    assert wrong_password.status_code == disabled.status_code == 401
    assert wrong_password.json() == disabled.json()
    assert wrong_password.json()["detail"] == "Invalid username or password"


def test_user_administration_requires_admin(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    alice = login_user(client, "alice", VIEWER_PASSWORD)

    for response in (
        client.post("/users", json={"username": "bob", "password": VIEWER_PASSWORD}, headers=bearer(alice["token"])),
        client.get("/users", headers=bearer(alice["token"])),
        client.patch(f"/users/{created['id']}", json={"disabled": True}, headers=bearer(alice["token"])),
        client.delete(f"/users/{created['id']}", headers=bearer(alice["token"])),
    ):
        assert response.status_code == 403

    for response in (
        client.post("/users", json={"username": "bob", "password": VIEWER_PASSWORD}),
        client.get("/users"),
        client.patch(f"/users/{created['id']}", json={"disabled": True}),
        client.delete(f"/users/{created['id']}"),
    ):
        assert response.status_code == 401


def test_break_glass_admin_administers_users(client: TestClient) -> None:
    glass = break_glass_login(client)

    assert client.get("/users", headers=bearer(glass["token"])).json() == []
    created = client.post(
        "/users",
        json={"username": "alice", "password": VIEWER_PASSWORD, "role": "admin"},
        headers=bearer(glass["token"]),
    )

    assert created.status_code == 201
    assert created.json()["role"] == "admin"


def test_user_administration_validation(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD, email="alice@example.com")
    created_id = created["id"]

    duplicate_username = client.post(
        "/users", json={"username": "ALICE", "password": VIEWER_PASSWORD}, headers=bearer(tokens["token"])
    )
    duplicate_email = client.post(
        "/users",
        json={"username": "bob", "password": VIEWER_PASSWORD, "email": "Alice@Example.COM"},
        headers=bearer(tokens["token"]),
    )
    unknown_role = client.post(
        "/users", json={"username": "bob", "password": VIEWER_PASSWORD, "role": "owner"}, headers=bearer(tokens["token"])
    )
    short_password = client.post(
        "/users", json={"username": "bob", "password": "short"}, headers=bearer(tokens["token"])
    )
    blank_username = client.post(
        "/users", json={"username": "   ", "password": VIEWER_PASSWORD}, headers=bearer(tokens["token"])
    )
    unknown_patch = client.patch("/users/does-not-exist", json={"disabled": True}, headers=bearer(tokens["token"]))
    role_change = client.patch(
        f"/users/{created_id}", json={"disabled": False, "role": "admin"}, headers=bearer(tokens["token"])
    )

    assert duplicate_username.status_code == 409
    assert duplicate_email.status_code == 409
    assert unknown_role.status_code == 422
    assert short_password.status_code == 422
    assert blank_username.status_code == 422
    assert unknown_patch.status_code == 404
    # `role` became mutable in Mf-2nbc (admin only, last-admin guarded), so a
    # patch that also changes the role is now accepted instead of rejected.
    assert role_change.status_code == 200
    assert role_change.json()["role"] == "admin"


def test_refresh_tokens_are_stored_hashed(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    with engine.connect() as conn:
        dump = str(conn.exec_driver_sql("SELECT * FROM sessions").fetchall())

    assert tokens["refresh_token"] not in dump
    assert sessions.hash_refresh_token(tokens["refresh_token"]) in dump


def test_expired_access_token_is_rejected(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    row = session_row(tokens["refresh_token"])
    now = int(time.time())
    expired = jwt.encode(
        {
            "sub": row.user_id,
            "sid": row.id,
            "typ": "access",
            "role": "admin",
            "username": row.username,
            "iat": now - 3600,
            "exp": now - 1800,
        },
        auth.AUTH_SECRET,
        algorithm=auth.AUTH_ALGO,
    )

    assert client.get("/assets", headers=bearer(expired)).status_code == 401


def test_access_expiry_is_enforced_server_side(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    with Session(engine) as db:
        row = sessions.find_by_refresh_hash(db, sessions.hash_refresh_token(tokens["refresh_token"]))
        row.access_expires_at = int(time.time()) - 1
        db.add(row)
        db.commit()

    assert client.get("/assets", headers=bearer(tokens["token"])).status_code == 401


def test_legacy_tokens_without_a_session_or_type_are_rejected(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    row = session_row(tokens["refresh_token"])
    now = int(time.time())
    legacy = jwt.encode({"sub": row.username, "iat": now, "exp": now + 3600}, auth.AUTH_SECRET, algorithm=auth.AUTH_ALGO)
    untyped = jwt.encode(
        {"sub": row.user_id, "sid": row.id, "iat": now, "exp": now + 3600},
        auth.AUTH_SECRET,
        algorithm=auth.AUTH_ALGO,
    )

    assert client.get("/assets", headers=bearer(legacy)).status_code == 401
    assert client.get("/assets", headers=bearer(untyped)).status_code == 401


def test_query_token_no_longer_authorizes(client: TestClient) -> None:
    """`?token=` was retired; a URL carries only a `?sig=` file grant now."""
    tokens = bootstrap_admin(client)

    for path in ("/assets", "/me"):
        response = client.get(path, params={"token": tokens["token"]})

        assert response.status_code == 401, f"{path} accepted a session token in the query: {response.text}"
        assert response.json()["detail"] == "Unauthorized"


def test_refresh_and_logout_accept_a_bearer_token(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    refreshed = client.post("/refresh", headers=bearer(tokens["refresh_token"]))

    assert refreshed.status_code == 200, refreshed.text
    rotated = refreshed.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]

    assert client.post("/logout", headers=bearer(rotated["refresh_token"])).status_code == 204
    assert client.post("/refresh", json={"refresh_token": rotated["refresh_token"]}).status_code == 401


def test_rotation_keeps_the_absolute_refresh_expiry(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    before = session_row(tokens["refresh_token"])

    rotated = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    after = session_row(rotated["refresh_token"])

    assert after.id == before.id
    assert after.refresh_expires_at == before.refresh_expires_at
    assert after.created_at == before.created_at
    assert after.last_used_at >= before.last_used_at
    assert after.access_expires_at > int(time.time())


# --- retiring an account (Mf-rnrn) -----------------------------------------

LAST_ADMIN_DETAIL = "at least one enabled administrator is required"


def delete_user(client: TestClient, admin_token: str, user_id: str):
    return client.delete(f"/users/{user_id}", headers=bearer(admin_token))


def test_admin_retires_an_account_and_it_can_no_longer_sign_in(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    alice = login_user(client, "alice", VIEWER_PASSWORD)

    retired = delete_user(client, tokens["token"], created["id"])

    assert retired.status_code == 204, retired.text
    assert retired.content == b""
    remaining = [user["username"] for user in client.get("/users", headers=bearer(tokens["token"])).json()]
    assert "alice" not in remaining
    # The account is gone, not disabled: its live session dies with it and the
    # credentials no longer authenticate.
    assert client.get("/assets", headers=bearer(alice["token"])).status_code == 401
    assert client.post("/login", json={"username": "alice", "password": VIEWER_PASSWORD}).status_code == 401


def test_retiring_an_account_deletes_its_sessions_and_identity_children(client: TestClient) -> None:
    """Every child row with a plain NO ACTION foreign key goes before the account."""
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    login_user(client, "alice", VIEWER_PASSWORD)
    with Session(engine) as db:
        db.add(MfaRecoveryCode(user_id=created["id"], code_hmac="not-a-real-hmac", created_at="2024-01-01T00:00:00+00:00"))
        db.add(
            OidcIdentity(
                issuer="https://idp.example.com",
                subject="sub-1",
                user_id=created["id"],
                created_at="2024-01-01T00:00:00+00:00",
            )
        )
        # `project.owner_id` is ON DELETE SET NULL, so the project survives.
        db.commit()
        project = Project(name="Owned by alice", owner_id=created["id"], created_at="2024-01-01T00:00:00+00:00", updated_at="2024-01-01T00:00:00+00:00")
        db.add(project)
        db.commit()
        project_id = project.id

    assert delete_user(client, tokens["token"], created["id"]).status_code == 204

    with Session(engine) as db:
        assert db.exec(select(UserSession).where(UserSession.user_id == created["id"])).first() is None
        assert db.exec(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == created["id"])).first() is None
        assert db.exec(select(OidcIdentity).where(OidcIdentity.user_id == created["id"])).first() is None
        orphan = db.get(Project, project_id)
        assert orphan is not None
        assert orphan.owner_id is None
        db.delete(orphan)
        db.commit()


def test_the_last_admin_cannot_retire_itself(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    me = client.get("/me", headers=bearer(tokens["token"])).json()

    refused = delete_user(client, tokens["token"], me["id"])

    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == LAST_ADMIN_DETAIL
    # Refused, not half-applied: the caller is still an administrator.
    assert client.get("/users", headers=bearer(tokens["token"])).status_code == 200


def test_a_disabled_second_admin_does_not_let_the_last_admin_retire_itself(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    me = client.get("/me", headers=bearer(tokens["token"])).json()
    second = create_user(client, tokens["token"], "second", VIEWER_PASSWORD, role="admin")
    disabled = client.patch(f"/users/{second['id']}", json={"disabled": True}, headers=bearer(tokens["token"]))
    assert disabled.status_code == 200, disabled.text

    refused = delete_user(client, tokens["token"], me["id"])

    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == LAST_ADMIN_DETAIL


def test_a_second_enabled_admin_lets_the_last_admin_retire_itself(client: TestClient) -> None:
    tokens = bootstrap_admin(client)
    me = client.get("/me", headers=bearer(tokens["token"])).json()
    create_user(client, tokens["token"], "second", VIEWER_PASSWORD, role="admin")

    assert delete_user(client, tokens["token"], me["id"]).status_code == 204
    assert client.get("/users", headers=bearer(tokens["token"])).status_code == 401


def test_retiring_an_unknown_account_is_a_404(client: TestClient) -> None:
    tokens = bootstrap_admin(client)

    response = delete_user(client, tokens["token"], "00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "no such user"


def test_a_retired_accounts_audit_rows_keep_their_actor_snapshot(client: TestClient) -> None:
    """The rows the account wrote must read exactly as they did before the delete."""
    tokens = bootstrap_admin(client)
    created = create_user(client, tokens["token"], "alice", VIEWER_PASSWORD)
    login_user(client, "alice", VIEWER_PASSWORD)
    second = login_user(client, "alice", VIEWER_PASSWORD)
    # An audited action taken BY the account that is about to be retired: revoke
    # one of its own devices, which writes `session.revoke` under alice.
    own_devices = client.get("/me/sessions", headers=bearer(second["token"])).json()
    other = [row["id"] for row in own_devices if not row["current"]]
    assert other, "the second login should have left a non-current device"
    revoked = client.delete(f"/me/sessions/{other[0]}", headers=bearer(second["token"]))
    assert revoked.status_code == 204, revoked.text

    def audit_snapshot(user_id: str) -> list[dict[str, str]]:
        """Every audit row this account wrote, exactly as stored.

        The log is append-only across the whole session, so other tests' rows are
        in the table too: the comparison is scoped to the account's own id, which
        is what the delete must leave alone.
        """
        with Session(engine) as db:
            rows = db.exec(select(AuditEvent).where(AuditEvent.actor_user_id == user_id)).all()
        return [
            {
                "id": row.id,
                "actor": row.actor,
                "actor_user_id": row.actor_user_id or "",
                "actor_role": row.actor_role,
                "action": row.action,
                "target": row.target,
                "detail_json": row.detail_json or "",
            }
            for row in rows
        ]

    before = audit_snapshot(created["id"])
    assert before, "the fixture's own audited action wrote no row"
    assert {row["actor"] for row in before} == {"alice"}
    assert {row["actor_role"] for row in before} == {"viewer"}
    assert "session.revoke" in {row["action"] for row in before}

    assert delete_user(client, tokens["token"], created["id"]).status_code == 204

    assert audit_snapshot(created["id"]) == before
    # The retired account's own row is visible to the audit reader, attributed.
    listed = client.get("/audit", params={"action": "session.revoke"}, headers=bearer(tokens["token"])).json()
    row = next(event for event in listed["events"] if event["actor_user_id"] == created["id"])
    assert row["actor"] == "alice"
    assert row["actor_role"] == "viewer"
