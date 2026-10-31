"""The two first-run setup routes (Mf-lyj2): a pre-flight and the one write.

Both are PUBLIC, and for the reason `/login` is: they run before any account
exists, so there is no principal to authenticate. That makes them the only
unauthenticated mutation in the API, and the reason every decision they make lives
in `first_run` - the window state, the policy, the atomic claim - rather than in a
handler a reader has to take on trust. The handlers here are the composition:
pre-check, claim, mint, stage the row, revoke break-glass, one commit.

Three rules this module exists to keep:

* **One transaction.** A second `auth.login()` after the insert would leave
  "administrator created, no session" reachable on any failure in between, and it
  would hash the password twice. The session is minted from the row the claim just
  wrote, in the same commit.
* **The transaction-safety rule of `accounts.create_user`.** It rolls back on a
  duplicate, which ends the transaction the claim opened. So the `AccountError`
  path does nothing else with the session: no audit row, no break-glass revoke,
  no commit. `routers/auth_users.py`'s `/users` handler is the same idiom.
* **No password, ever, outside the request body.** Not in a log line, not in the
  response, not in the audit detail; the response is a token pair and a notice.
  The 422 body names the violated *rules*, never the submitted value.
"""

import logging

from fastapi import APIRouter, HTTPException, Request, Response
from sqlmodel import Session

import accounts
import audit
import auth
import first_run
import login_throttle as login_throttle_module
import sessions
from db import engine
from schemas import FirstRunSetupRequest, FirstRunSetupResponse, FirstRunStatusResponse, RuleDoc

log = logging.getLogger(__name__)

# What the operator has to do next, in the one place the client reads it. The two
# halves matter equally: the flag stays on until it is unset, and the break-glass
# pair is now dead weight that reads like a backdoor.
NOTICE = (
    "First-run setup created the administrator. Remove `AUTH_PASSWORD` from `.env` and unset "
    "`AUTH_FIRST_RUN_SETUP`, then restart the API."
)

THROTTLED_DETAIL = "Too many failed first-run setup attempts. Try again later."
LOST_CLAIM_DETAIL = "another administrator was created first; this setup window is closed"

router = APIRouter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _refuse(refusal: first_run.Refusal) -> HTTPException:
    return HTTPException(status_code=refusal.status_code, detail=refusal.detail)


def _policy_detail(violations: list[first_run.Rule]) -> dict:
    """The 422 body: a dict `detail`, which is FastAPI's idiom for a structured error.

    The web client parses `detail.rules` to put each complaint next to the field
    it belongs to. No submitted value is echoed - only the rule ids and the
    server's own copy of each message.
    """
    return {
        "message": "password does not meet the policy",
        "rules": [{"rule": violation.rule, "message": violation.message} for violation in violations],
    }


@router.get("/auth/first-run/setup", response_model=FirstRunStatusResponse)
def first_run_status(response: Response):
    """Report whether the window is open and what the password must satisfy.

    A GET because it is a pre-flight the login screen makes on every load, and it
    writes nothing. `no-store` because the answer changes the moment the first
    administrator exists, and a cached "available: true" would leave the form on
    screen against a window that is already shut.
    """
    with Session(engine) as s:
        refusal = first_run.setup_refusal(s)
        if refusal is not None:
            raise _refuse(refusal)
    response.headers["Cache-Control"] = "no-store"
    return FirstRunStatusResponse(
        available=True,
        min_password_length=first_run.MIN_PASSWORD_LENGTH,
        rules=[RuleDoc(rule=rule.rule, message=rule.message) for rule in first_run.PASSWORD_RULES],
    )


@router.post("/auth/first-run/setup", response_model=FirstRunSetupResponse, status_code=201)
def first_run_setup(body: FirstRunSetupRequest, request: Request, response: Response):
    """Create the first administrator and sign them in, in one transaction.

    201 rather than 200: a `users` row came into existence, and the response
    carries the same token pair `POST /login` returns so the client lands signed
    in. That is deliberate - the window shut the instant this row existed, and the
    break-glass sessions died in the same commit, so bouncing the operator back to
    a login form to retype a password they chose ten seconds ago would prove
    nothing and risk a lockout on a typo.

    429 (throttled) and 422 (policy) both record a failure against the one fixed
    bucket; the 404/409 window refusals never touch it, so a closed window cannot
    be used to lock a live one.
    """
    client_ip = _client_ip(request)
    with Session(engine) as s:
        # The pre-check runs SELECTs only. `first_run.claim_first_admin` must be the
        # first write on this session, and a SELECT does not open a transaction in
        # pysqlite's legacy mode - the guard at the claim site enforces that.
        refusal = first_run.setup_refusal(s)
        if refusal is not None:
            raise _refuse(refusal)
        retry_after = login_throttle_module.first_run_limiter.retry_after(first_run.FIRST_RUN_THROTTLE_KEY)
        if retry_after:
            log.warning("First-run setup throttled from %s (retry after %ss)", client_ip, retry_after)
            raise HTTPException(status_code=429, detail=THROTTLED_DETAIL, headers={"Retry-After": str(retry_after)})
        violations = first_run.check_password(body.username, body.password, body.confirm_password)
        if violations:
            login_throttle_module.first_run_limiter.record_failure(first_run.FIRST_RUN_THROTTLE_KEY)
            # Usernames only: a rejected password is exactly the value that must not
            # reach a log line, a traceback or an error report.
            log.warning("First-run setup refused for username %r from %s: policy", body.username.strip(), client_ip)
            raise HTTPException(status_code=422, detail=_policy_detail(violations))
        try:
            user = first_run.claim_first_admin(s, body.username, body.password)
        except first_run.WindowClosed:
            login_throttle_module.first_run_limiter.record_failure(first_run.FIRST_RUN_THROTTLE_KEY)
            log.warning("First-run setup lost the claim from %s", client_ip)
            raise HTTPException(status_code=409, detail=LOST_CLAIM_DETAIL) from None
        except accounts.AccountError as exc:
            # Nothing else may touch `s` here: `create_user` rolled the claimed
            # transaction back, so anything staged now would commit WITHOUT the
            # admin row - and revoke_break_glass would then shut the only door.
            login_throttle_module.first_run_limiter.record_failure(first_run.FIRST_RUN_THROTTLE_KEY)
            log.warning("First-run setup refused for username %r from %s: %s", body.username.strip(), client_ip, exc)
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from None

        session_row, refresh_token = sessions.create(
            s,
            username=user.username,
            user_id=user.id,
            kind=sessions.PASSWORD_KIND,
            access_ttl=auth.AUTH_ACCESS_TOKEN_TTL,
            refresh_ttl=auth.AUTH_REFRESH_TTL_SECONDS,
            user_agent=request.headers.get("user-agent"),
            client_ip=client_ip,
        )
        role = sessions.role_for(session_row, user)
        token = auth.create_access_token(session_row, role)
        # The break-glass sessions die with the door that made them, and the count
        # goes into the row so an operator can see what the setup shut. Before the
        # `audit.stage` call because the detail names the count.
        revoked = sessions.revoke_break_glass(s)
        # The actor is a sentinel, never a user: nobody authenticated to do this.
        # `target` is the chosen username, so `GET /audit?target=<name>` finds the
        # row that created the account.
        actor = audit.Actor(audit.ACTOR_FIRST_RUN, audit.ACTOR_FIRST_RUN_ROLE, audit.ACTOR_FIRST_RUN_KIND, None)
        audit.stage(
            s,
            audit.context_for_actor(request, actor),
            audit.Event(
                audit.FIRST_RUN_SETUP,
                user.username,
                {
                    "user_id": user.id,
                    "username": user.username,
                    "role": user.role,
                    "source": "first_run_setup",
                    "break_glass_sessions_revoked": revoked,
                    "flag": "AUTH_FIRST_RUN_SETUP",
                },
            ),
        )
        s.commit()
    login_throttle_module.first_run_limiter.record_success(first_run.FIRST_RUN_THROTTLE_KEY)
    response.headers["Cache-Control"] = "no-store"
    return FirstRunSetupResponse(
        token=token,
        expires_in=auth.AUTH_ACCESS_TOKEN_TTL,
        refresh_token=refresh_token,
        notice=NOTICE,
    )
