// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

import ThemeSection from "./ThemeSection";
import { loadSettings, resetSettingsCache } from "../../lib/settings";
import type { AppSettings } from "../../lib/settings";

/**
 * jsdom reports a `window.localStorage` getter but, under Node's experimental
 * global localStorage, it resolves to `undefined`; tests install a real
 * in-memory Storage so `loadSettings` sees a working store.
 */
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
      store.set(key, String(value));
    },
  };
  Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
}

/** The label row wrapping an option's radio, i.e. the option as the user sees it. */
function optionRow(label: string): HTMLElement {
  const input = screen.getByRole("radio", { name: new RegExp(label) });
  const row = input.closest("label");
  if (!row) throw new Error(`missing the row for ${label}`);
  return row;
}

function renderSection(settings: AppSettings): Mock<(next: AppSettings) => void> {
  const onChange = vi.fn<(next: AppSettings) => void>();
  render(<ThemeSection settings={settings} onChange={onChange} onBack={vi.fn()} />);
  return onChange;
}

beforeEach(() => {
  installMemoryStorage();
  window.localStorage.clear();
  resetSettingsCache();
});

afterEach(() => {
  cleanup();
});

describe("ThemeSection default theme", () => {
  it("marks the default option as Default exactly once", () => {
    const settings = loadSettings();

    renderSection(settings);

    // The badge belongs to the brand default (Neon Purple) and to nothing else,
    // so a fresh install shows one Default, on the option it actually selects.
    expect(optionRow("Neon Purple").textContent).toContain("Default");
    expect(screen.getAllByText("Default")).toHaveLength(1);
  });

  it("marks the default even while another theme is selected", () => {
    renderSection({ ...loadSettings(), theme: { selected: "neon" } });

    // The pill names the app default, not the current pick.
    expect(optionRow("Neon Purple").textContent).toContain("Default");
    expect(optionRow("Neon Green").textContent).not.toContain("Default");
  });
});

describe("ThemeSection selection", () => {
  it("hands the picked theme back on the settings object", () => {
    const settings = loadSettings();
    const onChange = renderSection(settings);

    fireEvent.click(screen.getByRole("radio", { name: /Neon Green/ }));

    expect(onChange).toHaveBeenCalledTimes(1);
    const next = onChange.mock.calls[0][0];
    expect(next.theme.selected).toBe("neon");
    // Only the theme moves: every other setting is carried over untouched.
    expect(next.slicer).toEqual(settings.slicer);
    expect(next.previews).toEqual(settings.previews);
  });
});
