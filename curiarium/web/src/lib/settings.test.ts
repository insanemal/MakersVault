import { describe, expect, it } from "vitest";

import {
  DEFAULT_THEME_ID,
  THEME_OPTIONS,
  engraverLabelFor,
  resolveTheme,
  slicerLabelFor,
} from "./settings";

describe("application settings helpers", () => {
  it("uses stable labels for configured applications", () => {
    expect(slicerLabelFor("orca")).toBe("OrcaSlicer");
    expect(engraverLabelFor("lightburn")).toBe("LightBurn");
  });

  it("uses safe fallback labels for unknown applications", () => {
    expect(slicerLabelFor("unknown")).toBe("Slicer");
    expect(engraverLabelFor(null)).toBe("Engraving");
  });

  it("resolves system theme safely without a browser window", () => {
    expect(resolveTheme("system")).toBe("light");
    expect(resolveTheme("purple")).toBe("purple");
  });
});

describe("default theme", () => {
  it("defaults to the brand purple theme", () => {
    expect(DEFAULT_THEME_ID).toBe("purple");
    expect(THEME_OPTIONS.some(opt => opt.id === DEFAULT_THEME_ID)).toBe(true);
  });
});
