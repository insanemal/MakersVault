import React from "react";
import {
  FirstRunSetupError,
  firstRunSetup,
  type FirstRunRule,
  type FirstRunSetupResult,
  type FirstRunStatus,
} from "../lib/api";

type Props = {
  status: FirstRunStatus;
  onSuccess: (token: string, expires_in: number, refresh_token: string) => void;
  onWindowClosed?: (reason: string) => void;
};

// This local policy mirror is advisory UX: GET hands over the real messages and
// POST hands over the real verdicts, so drift here costs a round-trip and never
// a wrong outcome.
const MAX_PASSWORD_LENGTH = 1024;
const BLOCKLIST = [
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
];

const POLICY_COPY: Record<string, string> = {
  max_length: `password must be at most ${MAX_PASSWORD_LENGTH} characters`,
  contains_username: "password must not contain the username",
  blocklisted: "password must not be a common or predictable password",
  confirm_mismatch: "the two passwords do not match",
};

function characterCount(value: string): number {
  return Array.from(value).length;
}

function ruleCopy(status: FirstRunStatus, rule: string): string {
  const documentedRule = status.rules.find(item => item.rule === rule);
  if (documentedRule) return documentedRule.message;
  if (rule === "min_length") return `password must be at least ${status.min_password_length} characters`;
  return POLICY_COPY[rule] ?? "password does not meet this rule";
}

function passwordViolations(
  status: FirstRunStatus,
  username: string,
  password: string,
  confirm: string,
): FirstRunRule[] {
  const failed: string[] = [];
  if (characterCount(password) < status.min_password_length) failed.push("min_length");
  if (characterCount(password) > MAX_PASSWORD_LENGTH) failed.push("max_length");

  const foldedUsername = username.trim().toLowerCase();
  if (foldedUsername && password.toLowerCase().includes(foldedUsername)) failed.push("contains_username");

  const normalizedPassword = password.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");
  if (BLOCKLIST.some(term => normalizedPassword.startsWith(term))) failed.push("blocklisted");
  if (confirm !== password) failed.push("confirm_mismatch");

  return failed.map(rule => ({ rule, message: ruleCopy(status, rule) }));
}

export default function FirstRunSetup({ status, onSuccess, onWindowClosed }: Props) {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [ruleErrors, setRuleErrors] = React.useState<FirstRunRule[]>([]);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);
  const [closedWindowReason, setClosedWindowReason] = React.useState<string | null>(null);
  const [pendingTokens, setPendingTokens] = React.useState<FirstRunSetupResult | null>(null);

  React.useEffect(() => {
    if (closedWindowReason) onWindowClosed?.(closedWindowReason);
  }, [closedWindowReason, onWindowClosed]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setRuleErrors([]);
    setErrorMessage(null);

    const violations = passwordViolations(status, username, password, confirm);
    if (violations.length > 0) {
      setRuleErrors(violations);
      return;
    }

    setSubmitting(true);
    try {
      const result = await firstRunSetup(username, password, confirm);
      setPassword("");
      setConfirm("");
      setPendingTokens(result);
    } catch (error: unknown) {
      if (error instanceof FirstRunSetupError) {
        setRuleErrors(error.rules);
        if (error.rules.length === 0) {
          setErrorMessage(error.message);
          if (error.status === 404 || error.status === 409) {
            setClosedWindowReason(error.message);
          }
        }
      } else if (error instanceof Error) {
        setErrorMessage(error.message);
      } else {
        setErrorMessage("First-run setup failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  function continueToVault(): void {
    if (!pendingTokens) return;
    const result = pendingTokens;
    setPendingTokens(null);
    onSuccess(result.token, result.expires_in, result.refresh_token ?? "");
  }

  if (pendingTokens) {
    return (
      <section aria-labelledby="first-run-success-heading" className="space-y-4">
        <div className="space-y-2">
          <h2 id="first-run-success-heading" className="text-lg font-semibold">
            Administrator created
          </h2>
          <p className="text-sm text-muted">{pendingTokens.notice}</p>
        </div>
        <button
          type="button"
          onClick={continueToVault}
          className="w-full px-3 py-2 rounded-md bg-accent font-medium"
        >
          Continue to the vault
        </button>
      </section>
    );
  }

  return (
    <form className="space-y-4" onSubmit={handleSubmit}>
      {ruleErrors.length > 0 && (
        <div role="alert" className="mb-4 rounded-md bg-red-100 text-red-900 dark:bg-red-900/30 dark:text-red-100 px-3 py-2 text-sm">
          <p className="font-medium">Password requirements:</p>
          <ul className="mt-1 list-disc pl-5">
            {ruleErrors.map((rule, index) => (
              <li key={`${rule.rule}-${index}`} data-rule={rule.rule}>
                {rule.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      {errorMessage && (
        <div role="alert" className="mb-4 rounded-md bg-red-100 text-red-900 dark:bg-red-900/30 dark:text-red-100 px-3 py-2 text-sm">
          {errorMessage}
        </div>
      )}
      <div className="flex flex-col gap-1">
        <label className="text-sm font-medium" htmlFor="first-run-username">
          Username
        </label>
        <input
          id="first-run-username"
          value={username}
          onChange={event => setUsername(event.target.value)}
          className="px-3 py-2 rounded-md border border-panel-strong bg-panel-strong"
          autoComplete="username"
          required
        />
      </div>
      <div className="flex flex-col gap-1">
        <label className="text-sm font-medium" htmlFor="first-run-password">
          Password
        </label>
        <input
          id="first-run-password"
          type="password"
          value={password}
          onChange={event => setPassword(event.target.value)}
          className="px-3 py-2 rounded-md border border-panel-strong bg-panel-strong"
          autoComplete="new-password"
          required
        />
      </div>
      <div className="flex flex-col gap-1">
        <label className="text-sm font-medium" htmlFor="first-run-confirm-password">
          Confirm password
        </label>
        <input
          id="first-run-confirm-password"
          type="password"
          value={confirm}
          onChange={event => setConfirm(event.target.value)}
          className="px-3 py-2 rounded-md border border-panel-strong bg-panel-strong"
          autoComplete="new-password"
          required
        />
      </div>
      <button
        type="submit"
        disabled={submitting}
        className="w-full px-3 py-2 rounded-md bg-accent font-medium disabled:opacity-60"
      >
        {submitting ? "Creating administrator..." : "Create administrator"}
      </button>
    </form>
  );
}
