// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_THEME_ID, loadSettings, resetSettingsCache, type ThemeId } from "./settings";

const STORAGE_KEY = "curiarium_settings";

/** A real in-memory Storage, because jsdom's own store can resolve to `undefined` under Node. */
function memoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    get length(): number {
      return store.size;
    },
    clear(): void {
      store.clear();
    },
    getItem(key: string): string | null {
      return store.has(key) ? store.get(key)! : null;
    },
    key(index: number): string | null {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string): void {
      store.delete(key);
    },
    setItem(key: string, value: string): void {
      store.set(key, String(value));
    },
  };
}

function installMemoryStore(name: "localStorage" | "sessionStorage"): void {
  Object.defineProperty(window, name, { configurable: true, value: memoryStorage() });
}

/** Leaves a stored settings blob behind the way an earlier visit would. */
function seedStoredTheme(theme: string): void {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ theme: { selected: theme } }));
}

beforeEach(() => {
  installMemoryStore("localStorage");
  installMemoryStore("sessionStorage");
  window.localStorage.clear();
  window.sessionStorage.clear();
  resetSettingsCache();
});

describe("default theme", () => {
  // Reads the stored selection directly; `resolveTheme` is never consulted here.
  it("gives a fresh install the brand purple theme", () => {
    expect(loadSettings().theme.selected).toBe("purple");
  });

  it.each<ThemeId>(["neon", "light", "dark", "system", "blue"])(
    "keeps a stored %s choice instead of overriding it with the default",
    stored => {
      seedStoredTheme(stored);
      resetSettingsCache();

      expect(loadSettings().theme.selected).toBe(stored);
    },
  );

  it("falls back to purple for an unrecognised stored theme", () => {
    seedStoredTheme("sepia");
    resetSettingsCache();

    expect(loadSettings().theme.selected).toBe(DEFAULT_THEME_ID);
  });
});
