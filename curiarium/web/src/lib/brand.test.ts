import { describe, expect, it } from "vitest";

import { logoForTheme } from "./brand";
import type { ResolvedTheme } from "./settings";

const EXPECTED_LOGOS: Array<[ResolvedTheme, string]> = [
  ["light", "/img/blacklogo.png"],
  ["dark", "/img/whitelogo.png"],
  ["neon", "/img/green_theme/Neon_Green_bgrm.png"],
  ["purple", "/img/purple_theme/Neon_Purple_logo_bgrm.png"],
  ["blue", "/img/blue_theme/Blue_Theme_logo_bgrm.png"],
];

describe("brand lockups", () => {
  it.each(EXPECTED_LOGOS)("maps %s to its own logo", (theme, expected) => {
    expect(logoForTheme(theme)).toBe(expected);
  });
});
