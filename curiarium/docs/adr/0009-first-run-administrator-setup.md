# ADR 0009: First-run administrator setup from the browser

**Status:** Accepted

**Accepted:** 2026-10-31

**Implementation:** ticket `Mf-lyj2`.

## Context

A fresh Curiarium had no supported way to create its first administrator from the
UI. The three doors that existed each needed something beforehand:

* **Break-glass** (`AUTH_USERNAME`/`AUTH_PASSWORD`) needs an environment pair the
  operator invents before the first launch, and it is deliberately fragile: it
  authenticates only while the users table is empty *and* the pair is genuinely
  set, so the first account of any role closes it. It is also the wrong shape for
  a first password - it lives in a file, in a compose manifest and often in shell
  history, and it cannot be revoked except by editing that file and restarting.
* **`POST /users`** needs an admin session. There is nothing to sign in with yet.
* **SSO/OIDC** cannot bootstrap: `oidc.provision_or_link` raises
  `NoAdminBootstrap` while `accounts.count_enabled_admins() == 0`, because a claim
  an operator can misconfigure may never mint an administrator (ADR 0006). That
  refusal is correct and stays.

So the honest state was: "edit `.env`, restart, log in with a shared environment
password, create a real account, edit `.env` again, restart again". Every step of
that is a place to leave the environment password in place, and the empty-pair
case - `AUTH_MODE=local`, `both` or `oidc` with a blank pair and an empty users
table - is a deployment with no way in at all.

Two constraints shaped the answer:

* **One process, one SQLite file, no worker sharing state** (AGENTS.md, ADR 0006).
  A setup protocol that needs a queue, a pending table with its own sweeper, or
  cross-request state is infrastructure this product does not have.
* **The window must close itself.** A one-time token that is generated but never
  consumed is a standing credential; a flag that must be remembered is a flag that
  gets forgotten on a box exposed to the internet.

## Decision

1. **An opt-in flag, an inherent window.** `AUTH_FIRST_RUN_SETUP` (default off)
   makes the surface available; the window itself is open exactly while
   `accounts.count_enabled_admins() == 0`. The first enabled administrator closes
   it whether or not the flag is still set, so a forgotten flag costs nothing. The
   flag is read at request time (`auth.AUTH_FIRST_RUN_SETUP`), not once at import,
   following the `auth.AUTH_ENABLED` convention the guards already use.

2. **Two public routes, one behaviour.** `GET` and `POST /auth/first-run/setup`.
   Both are `PUBLIC` in `permissions.ROUTE_PERMISSIONS`, because they run before any
   account exists - exactly the reason `/login` is public. Both refuse with:
   * `404 "first-run setup is not available"` while the flag is off, before
     anything else, so a deployment that never opted in does not admit the route
     exists;
   * `409` when authentication is disabled (`AUTH_MODE=off`, or the legacy default
     with a blank pair), naming the mode: there is no sign-in for an administrator
     to protect;
   * `409` when `AUTH_MODE=oidc`: that mode refuses local password sign-in and SSO
     cannot mint the first admin, so the window is a genuine dead end and the
     message has to say which knob to turn instead;
   * `404` again once an enabled administrator exists.

   A schema-*invalid* `POST` on a flag-off deployment gets FastAPI's own `422`
   before the handler runs, so "404 identical to GET" holds for schema-valid
   bodies. That is a documented precision, not a leak: the `422` says nothing
   about the window.

3. **409, not the 503 idiom.** The two refusal cases above reuse neither `403` nor
   `503`. `DISABLED_503_KEYS` is a two-sided pin (`tests/test_permissions_matrix.py`)
   over the auth endpoints that refuse *while authentication is off*, and
   `tests/test_audit_log.py` sweeps the same set; these two routes are not that
   family. They are refusals of a *deliberately opened* window, and the caller is
   not missing a credential - the server is missing an administrator. `409` (the
   request conflicts with the deployment's state) is the honest status, and it
   keeps the 503 set meaning exactly what it says.

4. **One atomic claim.** `first_run.claim_first_admin` issues
   `BEGIN IMMEDIATE` on the request's session *before* reading the admin count, then
   counts, then inserts. A plain check-then-insert does not merely race
   theoretically: on SQLite both requests succeed, both insert, and the deployment
   silently gets two administrators (reproduced 3/3 while writing this ticket). The
   write lock makes the loser block at `BEGIN` (WAL plus `busy_timeout=10000`), read
   the winner's committed row and refuse with a `409`, which is a different answer
   from the pre-check's `404` because it is a different fact: the window *was* open
   when this caller looked, and somebody else took it. Retrying can only fail, so
   the status says so.

   `BEGIN IMMEDIATE` only works as the **first write on its session** - pysqlite's
   legacy transaction mode already has a transaction open after any DML and SQLite
   answers `cannot start a transaction within a transaction`. The router therefore
   runs only SELECTs (the refusal pre-check) before it, and
   `first_run.begin_write_transaction` raises a named `RuntimeError` if that
   invariant is ever broken. If a future driver leaves legacy transaction mode the
   happy path fails loudly with a 500 instead of silently racing; that is the
   intended failure direction.

5. **`accounts.create_user`'s rollback contract.** It calls `session.rollback()` on
   `IntegrityError`, which *ends* the claimed transaction. The handler therefore
   does nothing else with the session on the `AccountError` path - the idiom
   `routers/auth_users.py` already uses for `POST /users`. Staging a session row, an
   audit row and `revoke_break_glass` after that rollback would commit with no
   administrator row: every break-glass session revoked while zero admins exist,
   which is the unrecoverable lockout `accounts.LastAdmin` exists to prevent.

6. **One transaction, and the operator is signed in.** claim -> `sessions.create` ->
   `auth.create_access_token` -> `sessions.revoke_break_glass` -> `audit.stage` ->
   one commit. Not `auth.login()` afterwards: a second transaction leaves
   "administrator created, no session" reachable, and it would hash the password
   twice. Bouncing the operator to the login form would make them retype a password
   they chose ten seconds ago, against a window that has already shut - a typo there
   is a lockout. A fresh account has no TOTP seed, so no second factor can be
   skipped, and the minted session has `mfa_verified_at NULL`: if the admin MFA
   policy is enabled later, admin routes 403 until enrolment, and `/mfa/enrol` is
   `READ`, so there is no dead end.

7. **A stricter password policy than the rest of the API: 12 characters.** The
   minimum is 12, not `accounts.MIN_PASSWORD_LENGTH` (8), and it also refuses a
   password equal to or containing the username, a password that equals or starts
   with a term on a short blocklist (`password`, `passw0rd`, `123456`, `qwerty`,
   `admin`, `curiarium`, `vault`, `secret`, ...), and a mismatched confirmation.
   All violations are returned together as a structured `422`
   (`{"detail": {"message", "rules": [{"rule", "message"}]}}`), with stable rule
   ids the form mirrors from the `GET`.

   **Why 12 and not 8.** This is the one account nobody can recover: there is no
   reset path that does not already require an administrator, and it is chosen once
   at a keyboard on a fresh install rather than typed daily. 12 is NIST SP
   800-63B's floor for a single factor and still fits a passphrase. The divergence
   from `/users` and the admin reset is deliberate and stays: those are daily-use
   accounts created by somebody who already got in.

   Both password fields are `Field(repr=False)`, so a stray `repr(body)` in a log
   line, a debugger or a traceback cannot print them. That governs reprs only:
   pydantic's own validation errors do echo the submitted input, exactly as
   `/login` does, which is a fact the configuration reference states.

8. **A dedicated throttle bucket, one fixed key.** `login_throttle.first_run_limiter`
   (its own `LoginThrottle`, reset at startup beside the other two). The key is the
   constant `first_run.FIRST_RUN_THROTTLE_KEY = "first-run"`, **not** the submitted
   username: the username space is attacker-controlled on an unauthenticated
   route, so a per-username bucket would multiply the argon2 budget up to
   `MAX_BUCKETS` (1024) hashes per lockout window. Policy rejections and lost claims
   record a failure; a success clears it; the `404`/`409` window refusals record
   nothing, so a closed window cannot be used to lock a live one. The response is
   `429` with `Retry-After`, like `/login`. An attacker who locks the bucket could
   instead simply claim the administrator - a strictly worse outcome for them - so
   the documented recovery is "restart the API".

9. **One audit row, and it names no user.** `audit.FIRST_RUN_SETUP =
   "first_run.setup"`, carried by `("POST", "/auth/first-run/setup")` in
   `ROUTE_ACTIONS`. The actor is a sentinel - `Actor("first-run-setup",
   "unauthenticated", "first-run", None)` - because nobody authenticated to create
   that account; `target` is the chosen username, so `GET /audit?target=<name>`
   finds the row that created the account. The detail carries `user_id`,
   `username`, `role`, `source`, `break_glass_sessions_revoked` and `flag`. Never a
   password or a hash.

10. **The boot says whether the window is open.** `main.lifespan`, after
    `run_migrations` (it needs the users table), logs one `INFO` line when the flag
    is on: open, closed with the count and "unset `AUTH_FIRST_RUN_SETUP`", or the
    refusal reason.

## Consequences

* A fresh deployment has one documented, browser-driven path to its first
  administrator, and it is the recommended one in `README.md`; break-glass and SSO
  remain for the cases they actually fit.
* **The window is a deliberate exposure while it is open.** Anyone who can reach the
  API can create the administrator: there is no credential to present, because none
  exists yet. That is inherent to the feature, not a defect in it - the alternatives
  all move the exposure somewhere less visible (a token in a log, a file on disk)
  rather than removing it. Mitigations: the flag is off by default, the surface
  404s when off, the window closes by itself at the first enabled admin, the
  throttle bounds the attempt rate, and `CONFIGURATION.md` and the boot log both
  tell the operator to unset the flag.
* A deployment that leaves `AUTH_FIRST_RUN_SETUP=1` forever is not exposed once an
  administrator exists - both routes 404 - but it does keep advertising a route
  that can never succeed, and the boot log keeps saying so.
* The setup password is not recoverable. There is no reset path that does not
  already need an administrator, which is why the policy is the stricter one.
* Two new public routes and one new audited route join the matrix (93 routes, 11
  public) and the audit taxonomy (49 actions, 42 route keys), with the pins in
  `tests/test_permissions_matrix.py`, `tests/test_permissions_docs.py`,
  `tests/test_snapshots.py` and `tests/test_audit_log.py` updated in the same
  change.
* `AUTH_FIRST_RUN_SETUP` is a new environment key, so it is forwarded by both
  compose manifests, documented in `.env.example` and in the configuration
  reference, and `tests/test_deploy_manifest_env.py` pins all three.

## Alternatives considered

- **Keep env-only break-glass and document it better.** Rejected: it is the status
  quo this ticket exists to fix. It requires inventing a credential before the
  first launch, it lives in a file that is often committed or shared, it cannot be
  revoked except by editing that file and restarting, and it leaves the
  "auth forced on, blank pair, empty users table" deployment with no way in at all.
- **A one-time token printed to the startup log** (the Jupyter/Grafana pattern).
  Rejected: the log is usually collected, shipped and retained, often by a service
  the operator does not control, so the token outlives the window that made it
  safe. It also needs the operator to have shell access at exactly the moment the
  container starts, which is the same requirement as editing `.env` - all of the
  friction, plus a standing credential in a file nobody thinks of as secret.
- **Open the window whenever the users table is empty, with no flag.** Rejected: it
  makes every fresh deployment that is reachable before its operator reaches it
  claimable by whoever gets there first, and it gives the operator no way to say
  "not yet". Opt-in means the exposure exists only when somebody asked for it.
- **A CLI or compose one-shot (`docker compose run api create-admin`).** Rejected
  as the *only* path: it presumes shell access to the host, which the
  portal-gated/Cosmos deployment documented in `CONFIGURATION.md` deliberately does
  not give, and it duplicates the password policy in a second entry point. It is a
  reasonable *additional* command and nothing here forbids adding one.
- **localhost-only binding for the setup routes.** Rejected: behind a reverse proxy
  - the documented deployment - every request arrives from the proxy's address, so
  the check either always passes (useless) or always fails (unusable), and
  `X-Forwarded-For` is client-controlled. Binding the *container* to localhost does
  not help either: the proxy is what publishes it.
- **A single-statement `INSERT INTO users (...) SELECT ... WHERE NOT EXISTS (SELECT
  1 FROM users WHERE role = 'admin')`.** Genuinely race-free - one statement, one
  implicit transaction, no dependency on the driver's `BEGIN` mode - and it is the
  strongest of the alternatives. Rejected because it bypasses `accounts.create_user`
  entirely: username cleaning, the role check, the email normalisation, the hash,
  the timestamps and the `IntegrityError` -> `DuplicateAccount` mapping would all be
  written a second time, in SQL, where a divergence is silent; and the ORM row for
  the just-inserted user would have to be re-fetched to mint the session from it.
  `BEGIN IMMEDIATE` reuses the one implementation and pays for it with a documented
  driver dependency instead.
- **Sending the operator back to the login form after setup.** Rejected: the window
  closes the instant the row exists and the break-glass sessions died in the same
  transaction, so the login they would be sent to is the account they just made,
  typed again from memory seconds later - a typo is a lockout on a deployment with
  no recovery path.
- **Reusing the `/login` throttle bucket.** Rejected: a `/login` spray would then
  lock the one-time bootstrap out (and a slow setup would lock logins out), which is
  a denial-of-service lever rather than a defence. `mfa_limiter` set the precedent.
- **Isolating the setup call in its own router of one route pair, on the app
  directly.** Rejected: `permissions.assert_routes_classified` enumerates from
  `main.API_ROUTERS`, so a route declared on the app is a route the guard cannot see.

## Rollback

The change is revertible without a schema rollback: there is no migration. Reverting
removes the two routes, the `first_run` module, the one audit action, the one
`ROUTE_ACTIONS` entry and the `AUTH_FIRST_RUN_SETUP` variable; existing
`first_run.setup` rows and the administrators they created stay, which is the
correct outcome - they are accounts, not setup state. `AUTH_FIRST_RUN_SETUP` left in
an environment after a revert is an inert, unread variable.

Operationally: an administrator created through this window is an ordinary `users`
row with a password hash, so nothing downstream needs undoing. If the deployment
would rather go back to break-glass, the row has to go: there is no delete-account
route, and `PATCH /users/{user_id}` cannot demote the last enabled administrator
(`accounts.LastAdmin` refuses it), so remove it directly (`DELETE FROM users WHERE
id = ...` against the SQLite file). Break-glass then reopens, because its threshold
is the empty users *table*, not the admin count.

## Verification

- `tests/test_first_run_setup.py` drives the whole contract through
  `TestClient(main.app)`: 404 on both routes with the flag off and no row created;
  the `GET` policy payload and `Cache-Control: no-store`; a `201` that creates an
  `admin`, returns a token that works on `GET /me`, and carries the notice; both
  routes 404 once an administrator exists; `409` naming the mode for
  `AUTH_MODE=off` and for `AUTH_MODE=oidc`; one `422` per policy rule naming its id
  and a combined `422` for several at once; the throttle's `429` with
  `Retry-After`; a break-glass session revoked by the setup and its token 401
  afterwards; exactly one audit row with the sentinel actor, `actor_user_id NULL`,
  and the chosen username as target; and a password that appears in no log line,
  response body or audit row.
- The concurrency proof is two-layered. Five rounds of two simultaneous `POST`s
  through `TestClient` on a `threading.Barrier` - one `201` and one `409` per round,
  one enabled administrator at the end, with the throttle bucket reset between
  rounds - plus a direct two-session race at `first_run.claim_first_admin` itself,
  asserting the loser raises `WindowClosed` and that exactly one `users` row exists.
  Removing `BEGIN IMMEDIATE` turns both into two successful inserts, which is what
  the guard was checked against while writing the ticket.
- The `DuplicateAccount` path is tested for *no partial write*: the claimed
  transaction is rolled back by `accounts.create_user`, so there is no user row, no
  session row and no audit row, and a live break-glass session still authenticates
  afterwards.
- `tests/test_permissions_matrix.py` sweeps both new public routes for the 93-route
  matrix (11 public / 33 read / 19 contribute / 13 write / 17 admin) at every role
  and in the auth-disabled mode, with a schema-valid body for the `POST` (FastAPI
  validates before the handler, so a bodyless spec would be a `422` and prove
  nothing); `tests/test_permissions_docs.py` pins the documented size and the two
  rows in `docs/PERMISSIONS.md`.
- `tests/test_audit_log.py` sweeps the new audited route (flag patched on, accounts
  truncated, throttle reset) and maps it to the sentinel actor kind, so the generic
  "the admin did it" assertions do not apply to it.
- `tests/test_snapshots.py` pins `len(audit.ACTIONS) == 49`,
  `len(audit.ROUTE_ACTIONS) == 42` and the route-coverage sentence in
  `docs/AUDIT.md`; `tests/test_openapi_contract.py` pins the four new schema
  components (`FirstRunSetupRequest`, `FirstRunSetupResponse`,
  `FirstRunStatusResponse`, `RuleDoc`); `tests/test_deploy_manifest_env.py` pins the
  forwarding fallback, the `.env.example` entry and the `CONFIGURATION.md` row.
- `tests/conftest.py` pins the flag off for the whole suite, so a developer who
  exported it cannot flip the permission and audit sweeps' `404` expectations.

## Superseding conditions

This ADR is superseded if any of the following becomes true:

- the window stops closing itself at the first enabled administrator, or its
  threshold stops being the *enabled admin* count (break-glass's is the empty users
  table; the two thresholds are deliberately different and must not be conflated);
- the surface stops being opt-in, or the flag-off case stops answering `404`;
- the claim stops taking the write lock before the count, or stops reusing
  `accounts.create_user` (a single-statement `INSERT ... SELECT` implementation
  would supersede the atomic-claim section specifically);
- the password policy drops below 12 characters, loses the username/blocklist
  checks, or `accounts.MIN_PASSWORD_LENGTH` becomes the rule everywhere;
- `accounts.create_user` stops rolling back on `IntegrityError`, which would make
  the no-partial-write contract unnecessary rather than violated;
- the setup stops minting a session, so the operator is sent to the login form;
- the throttle key becomes per-username, or the route starts recording window
  refusals as failures;
- the audit actor stops being a sentinel, or the row starts naming a user id.
