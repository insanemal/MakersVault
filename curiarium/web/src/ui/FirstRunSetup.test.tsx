// @vitest-environment jsdom
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("../lib/api", async () => {
  const auth = await import("../lib/api/auth");
  return {
    getFirstRunStatus: vi.fn(async () => null),
    getOidcStatus: vi.fn(async () => ({ enabled: false })),
    firstRunSetup: vi.fn(),
    FirstRunSetupError: auth.FirstRunSetupError,
    login: vi.fn(),
    mfaVerify: vi.fn(),
    isMfaChallenge: auth.isMfaChallenge,
    oidcStartUrl: () => "http://api.test/auth/oidc/start",
    ssoErrorCopy: auth.ssoErrorCopy,
  };
});

import { FirstRunSetupError, firstRunSetup, getFirstRunStatus, login } from "../lib/api";
import Login from "./Login";
import FirstRunSetup from "./FirstRunSetup";
import type { FirstRunRule, FirstRunStatus } from "../lib/api";

const getFirstRunStatusMock = vi.mocked(getFirstRunStatus);
const firstRunSetupMock = vi.mocked(firstRunSetup);
const loginMock = vi.mocked(login);

const policyRules: FirstRunRule[] = [
  { rule: "min_length", message: "password must be at least 12 characters" },
  { rule: "max_length", message: "password must be at most 1024 characters" },
  { rule: "contains_username", message: "password must not contain the username" },
  { rule: "blocklisted", message: "password must not be a common or predictable password" },
  { rule: "confirm_mismatch", message: "the two passwords do not match" },
];

const availableStatus: FirstRunStatus = {
  available: true,
  min_password_length: 12,
  rules: policyRules,
};

/** jsdom's localStorage can resolve to `undefined` under Node's global. */
function installMemoryStorage(): void {
  const store = new Map<string, string>();
  const storage: Storage = {
    get length(): number {
      return store.size;
    },
    clear(): void {
      store.clear();
    },
    getItem(key: string): string | null {
      return store.has(key) ? (store.get(key) as string) : null;
    },
    key(index: number): string | null {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string): void {
      store.delete(key);
    },
    setItem(key: string, value: string): void {
      store.set(key, value);
    },
  };
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true });
}

function setField(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function fillSetupForm(password = "a-different-long-passphrase"): void {
  setField("Username", "maker");
  setField("Password", password);
  setField("Confirm password", password);
}

beforeEach(() => {
  installMemoryStorage();
  getFirstRunStatusMock.mockReset();
  getFirstRunStatusMock.mockResolvedValue(null);
  firstRunSetupMock.mockReset();
  loginMock.mockReset();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("first-run setup entry on the sign-in page", () => {
  it("shows the setup form only when the status says it is available", async () => {
    getFirstRunStatusMock.mockResolvedValue(availableStatus);

    render(<Login onSuccess={vi.fn()} apiUp={true} theme="light" />);

    expect(await screen.findByLabelText("Confirm password")).toBeTruthy();
    expect(screen.getByText("Set up your administrator account")).toBeTruthy();
    expect(screen.queryByText("Sign in")).toBeNull();
  });

  it("shows no setup form when the endpoint returns 404", async () => {
    getFirstRunStatusMock.mockResolvedValue(null);

    render(<Login onSuccess={vi.fn()} apiUp={true} theme="light" />);

    expect(await screen.findByText("Sign in")).toBeTruthy();
    expect(screen.queryByLabelText("Confirm password")).toBeNull();
  });

  it("returns to login with the server reason when setup closes during submission", async () => {
    const reason = "another administrator was created first; this setup window is closed";
    getFirstRunStatusMock.mockResolvedValue(availableStatus);
    firstRunSetupMock.mockRejectedValue(new FirstRunSetupError(reason, [], 409));

    render(<Login onSuccess={vi.fn()} apiUp={true} theme="light" />);
    await screen.findByLabelText("Confirm password");
    fillSetupForm();
    fireEvent.click(screen.getByText("Create administrator"));

    expect((await screen.findByRole("status")).textContent).toBe(reason);
    expect(screen.getByText("Sign in")).toBeTruthy();
    expect(document.querySelector("input[autocomplete='current-password']")).toBeTruthy();
    expect(screen.queryByLabelText("Confirm password")).toBeNull();
  });

  it("shows a quiet mode refusal and leaves ordinary login usable", async () => {
    getFirstRunStatusMock.mockResolvedValue({ reason: "AUTH_MODE=oidc refuses local password sign-in." });
    loginMock.mockResolvedValue({ token: "existing-access", expires_in: 900, refresh_token: "existing-refresh" });
    const onSuccess = vi.fn();

    render(<Login onSuccess={onSuccess} apiUp={true} theme="light" />);

    expect((await screen.findByRole("status")).textContent).toContain("AUTH_MODE=oidc refuses local password sign-in.");
    expect(screen.getByText("Sign in")).toBeTruthy();
    const usernameInput = document.querySelector("input[autocomplete='username']");
    const passwordInput = document.querySelector("input[autocomplete='current-password']");
    if (!(usernameInput instanceof HTMLInputElement) || !(passwordInput instanceof HTMLInputElement)) {
      throw new Error("login form inputs are missing");
    }
    fireEvent.change(usernameInput, { target: { value: "admin" } });
    fireEvent.change(passwordInput, { target: { value: "current-password" } });
    fireEvent.click(screen.getByText("Sign in"));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith("existing-access", 900, "existing-refresh"));
    expect(loginMock).toHaveBeenCalledWith("admin", "current-password");
  });
});

describe("first-run administrator form", () => {
  it("mirrors password rules locally instead of sending a known-invalid password", async () => {
    render(<FirstRunSetup status={availableStatus} onSuccess={vi.fn()} />);
    fillSetupForm("makersvault-passphrase");
    fireEvent.click(screen.getByText("Create administrator"));

    const blocklistedRule = policyRules.find(rule => rule.rule === "blocklisted");
    if (!blocklistedRule) throw new Error("Blocklisted policy fixture is missing");
    expect(await screen.findByText(blocklistedRule.message)).toBeTruthy();
    expect(document.querySelector('li[data-rule="blocklisted"]')?.textContent).toBe(blocklistedRule.message);
    expect(firstRunSetupMock).not.toHaveBeenCalled();
  });

  it("shows retryable 422 policy messages without exposing internal rule identifiers", async () => {
    const returnedRules = policyRules.map(rule => ({ ...rule }));
    const onWindowClosed = vi.fn();
    firstRunSetupMock.mockRejectedValue(new FirstRunSetupError("password does not meet the policy", returnedRules, 422));
    render(<FirstRunSetup status={availableStatus} onSuccess={vi.fn()} onWindowClosed={onWindowClosed} />);
    fillSetupForm();
    fireEvent.click(screen.getByText("Create administrator"));

    const errorBox = await screen.findByRole("alert");
    for (const rule of returnedRules) {
      const item = errorBox.querySelector(`li[data-rule="${rule.rule}"]`);
      expect(item?.getAttribute("data-rule")).toBe(rule.rule);
      expect(item?.textContent).toBe(rule.message);
      expect(errorBox.textContent).not.toContain(rule.rule);
    }
    expect(screen.getByLabelText("Confirm password")).toBeTruthy();
    expect(onWindowClosed).not.toHaveBeenCalled();
  });

  it("shows the returned notice and keeps tokens until the explicit continue action", async () => {
    firstRunSetupMock.mockResolvedValue({
      token: "access-first-run",
      expires_in: 900,
      refresh_token: "refresh-first-run",
      notice: "Remove AUTH_PASSWORD from .env, unset AUTH_FIRST_RUN_SETUP, then restart the API.",
    });
    const onSuccess = vi.fn();
    render(<FirstRunSetup status={availableStatus} onSuccess={onSuccess} />);
    fillSetupForm();
    fireEvent.click(screen.getByText("Create administrator"));

    expect(await screen.findByText(/Remove AUTH_PASSWORD from \.env/)).toBeTruthy();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);

    fireEvent.click(screen.getByText("Continue to the vault"));
    expect(onSuccess).toHaveBeenCalledWith("access-first-run", 900, "refresh-first-run");
    expect(window.localStorage.length).toBe(0);
  });

  it("shows 409 and 429 details without replacing them with a generic validation error", async () => {
    for (const message of ["An administrator already exists.", "Try again after the retry delay."]) {
      firstRunSetupMock.mockRejectedValueOnce(new Error(message));
      const { unmount } = render(<FirstRunSetup status={availableStatus} onSuccess={vi.fn()} />);
      fillSetupForm();
      fireEvent.click(screen.getByText("Create administrator"));
      expect(await screen.findByText(message)).toBeTruthy();
      unmount();
    }
  });
});
