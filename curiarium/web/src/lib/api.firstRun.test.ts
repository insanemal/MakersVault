// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FirstRunSetupError,
  firstRunSetup,
  getFirstRunStatus,
  type FirstRunRule,
  type FirstRunSetupResult,
  type FirstRunStatus,
} from "./api";

type MockResponse = {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  headers: Headers;
};

type MockFetch = ReturnType<typeof vi.fn<(input: string, init?: RequestInit) => Promise<MockResponse>>>;

function respond(
  payload: unknown,
  init: { ok?: boolean; status?: number; headers?: Record<string, string> } = {},
): MockResponse {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => payload,
    headers: new Headers(init.headers ?? {}),
  };
}

function installFetch(response: MockResponse): MockFetch {
  const fetchMock = vi.fn<(input: string, init?: RequestInit) => Promise<MockResponse>>(async () => response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function setupBody(init: RequestInit): unknown {
  if (typeof init.body !== "string") throw new Error("expected a JSON request body");
  return JSON.parse(init.body);
}

const rules: FirstRunRule[] = [
  { rule: "min_length", message: "password must be at least 12 characters" },
  { rule: "blocklisted", message: "password must not be a common or predictable password" },
];

const status: FirstRunStatus = { available: true, min_password_length: 12, rules };
const result: FirstRunSetupResult = {
  token: "access-1",
  expires_in: 900,
  refresh_token: "refresh-1",
  notice: "Remove AUTH_PASSWORD from .env and restart the API.",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getFirstRunStatus", () => {
  it("parses the open window and requests it without cache", async () => {
    const fetchMock = installFetch(respond(status));

    await expect(getFirstRunStatus()).resolves.toEqual(status);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toContain("/auth/first-run/setup");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: "no-store" });
  });

  it("treats 404 as no window", async () => {
    installFetch(respond({ detail: "not available" }, { ok: false, status: 404 }));

    await expect(getFirstRunStatus()).resolves.toBeNull();
  });

  it("returns the mode refusal on 409 without throwing", async () => {
    installFetch(respond({ detail: "AUTH_MODE=oidc refuses local password sign-in" }, { ok: false, status: 409 }));

    await expect(getFirstRunStatus()).resolves.toEqual({ reason: "AUTH_MODE=oidc refuses local password sign-in" });
  });

  it("keeps a generic mode refusal when a 409 body is invalid JSON", async () => {
    const invalidJsonResponse = respond(null, { ok: false, status: 409 });
    invalidJsonResponse.json = async () => {
      throw new SyntaxError("Invalid JSON");
    };
    installFetch(invalidJsonResponse);

    await expect(getFirstRunStatus()).resolves.toEqual({
      reason: "First-run setup is unavailable for this authentication mode.",
    });
  });

  it("treats other responses, malformed success bodies, and network errors as no window", async () => {
    installFetch(respond({ detail: "unavailable" }, { ok: false, status: 503 }));
    await expect(getFirstRunStatus()).resolves.toBeNull();

    installFetch(respond({ available: false }));
    await expect(getFirstRunStatus()).resolves.toBeNull();

    const failingFetch = vi.fn<(input: string, init?: RequestInit) => Promise<MockResponse>>(async () => {
      throw new Error("offline");
    });
    vi.stubGlobal("fetch", failingFetch);
    await expect(getFirstRunStatus()).resolves.toBeNull();
  });
});

describe("firstRunSetup", () => {
  it("posts the confirmation and parses the token response", async () => {
    const fetchMock = installFetch(respond(result));

    await expect(firstRunSetup("maker", "a secure passphrase", "a secure passphrase")).resolves.toEqual(result);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/auth/first-run/setup");
    expect(init?.method).toBe("POST");
    expect(init?.cache).toBe("no-store");
    expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
    expect(setupBody(init ?? {})).toEqual({
      username: "maker",
      password: "a secure passphrase",
      confirm_password: "a secure passphrase",
    });
  });

  it("parses 422 into a FirstRunSetupError with the named rules", async () => {
    installFetch(
      respond(
        { detail: { message: "password does not meet the policy", rules } },
        { ok: false, status: 422 },
      ),
    );

    const error = await firstRunSetup("maker", "password", "mismatch").catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(FirstRunSetupError);
    expect(error).toMatchObject({
      message: "password does not meet the policy",
      status: 422,
      rules,
    });
  });

  it("surfaces the 409 administrator-exists detail", async () => {
    installFetch(respond({ detail: "an administrator already exists" }, { ok: false, status: 409 }));

    await expect(firstRunSetup("maker", "a secure passphrase", "a secure passphrase")).rejects.toThrow(
      "an administrator already exists",
    );
  });

  it("surfaces the 429 detail and does not throw away the response", async () => {
    installFetch(
      respond(
        { detail: "Too many setup attempts." },
        { ok: false, status: 429, headers: { "Retry-After": "30" } },
      ),
    );

    await expect(firstRunSetup("maker", "a secure passphrase", "a secure passphrase")).rejects.toThrow(
      "Too many setup attempts.",
    );
  });
});
