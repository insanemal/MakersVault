import { describe, expect, it } from "vitest";

import css from "../index.css?raw";

type Rgb = { r: number; g: number; b: number };
type Rgba = Rgb & { a: number };

/** The five theme blocks, in stylesheet order. */
const THEME_BLOCKS = [":root", "html.dark", "html.theme-neon", "html.theme-purple", "html.theme-blue"];

/** Tokens every theme block must define to be a usable theme. */
const REQUIRED_TOKENS = [
  "--mv-accent",
  "--mv-accent-strong",
  "--mv-accent-soft",
  "--mv-accent-border",
  "--mv-accent-contrast",
  "--mv-bg",
  "--mv-panel",
];

/** WCAG 2.x AA minimum for normal text. */
const AA_MINIMUM = 4.5;

const HEX_PATTERN = /#(?:[0-9a-f]{6}|[0-9a-f]{3})\b/gi;
const RGBA_PATTERN = /rgba?\(\s*([0-9.]+)[\s,]+([0-9.]+)[\s,]+([0-9.]+)(?:[\s,/]+([0-9.]+))?\s*\)/i;

/** Records `--custom-property: value` pairs from one block body, ignoring anything else. */
function recordDeclaration(target: Map<string, string>, declaration: string): void {
  const separator = declaration.indexOf(":");
  if (separator < 0) return;
  const name = declaration.slice(0, separator).trim();
  if (!name.startsWith("--")) return;
  target.set(name, declaration.slice(separator + 1).trim());
}

/**
 * Scans the stylesheet for the five top-level theme blocks and records each
 * declaration inside them.
 *
 * Depth is counted, not guessed: a block can only become a theme block when it
 * opens at top level, so `@layer components` and everything nested inside it
 * (`@apply`, `@screen`, ...) is skipped. Comments are stripped first because
 * they may contain braces that would corrupt the count.
 */
function parseThemeBlocks(source: string): Map<string, Map<string, string>> {
  const blocks = new Map<string, Map<string, string>>();
  const wanted = new Set<string>(THEME_BLOCKS);
  const text = source.replace(/\/\*[\s\S]*?\*\//g, "");
  let depth = 0;
  let buffer = "";
  let current: Map<string, string> | null = null;

  for (const char of text) {
    if (char === "{") {
      depth += 1;
      const selector = buffer.trim();
      current = depth === 1 && wanted.has(selector) ? new Map<string, string>() : null;
      if (current) blocks.set(selector, current);
      buffer = "";
    } else if (char === "}") {
      depth -= 1;
      current = null;
      buffer = "";
    } else if (char === ";") {
      if (current) recordDeclaration(current, buffer);
      buffer = "";
    } else if (depth <= 1) {
      buffer += char;
    }
  }
  return blocks;
}

/** Parses `#rgb` or `#rrggbb` into channels. */
function parseHex(value: string): Rgb {
  const digits = value.length === 4
    ? value.slice(1).split("").map(char => char + char).join("")
    : value.slice(1);
  return {
    r: parseInt(digits.slice(0, 2), 16),
    g: parseInt(digits.slice(2, 4), 16),
    b: parseInt(digits.slice(4, 6), 16),
  };
}

/** The base colour of a layered value: the last hex token, which sits under any `radial-gradient(...)`. */
function resolveSurface(value: string): Rgb {
  const matches = value.match(HEX_PATTERN);
  if (!matches || matches.length === 0) {
    throw new Error(`no hex surface colour in "${value}"`);
  }
  return parseHex(matches[matches.length - 1]);
}

/** Parses `rgb()` or `rgba()` into channels plus alpha (defaulting to opaque). */
function parseRgb(value: string): Rgba {
  const match = RGBA_PATTERN.exec(value);
  if (!match) {
    throw new Error(`no rgb() colour in "${value}"`);
  }
  const [, r, g, b, alpha] = match;
  return {
    r: Number(r),
    g: Number(g),
    b: Number(b),
    a: alpha === undefined ? 1 : Number(alpha),
  };
}

/** Alpha-over composite of `foreground` onto an opaque `background`. */
function composite(foreground: Rgba, background: Rgb): Rgb {
  const mix = (front: number, back: number): number => front * foreground.a + back * (1 - foreground.a);
  return {
    r: mix(foreground.r, background.r),
    g: mix(foreground.g, background.g),
    b: mix(foreground.b, background.b),
  };
}

/** WCAG 2.x relative luminance. */
function relativeLuminance(color: Rgb): number {
  const linear = (channel: number): number => {
    const srgb = channel / 255;
    return srgb <= 0.03928 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b);
}

/** WCAG 2.x contrast ratio, always >= 1. */
function contrastRatio(a: Rgb, b: Rgb): number {
  const [lighter, darker] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (lighter + 0.05) / (darker + 0.05);
}

type Palette = {
  accent: Rgb;
  accentStrong: Rgb;
  accentContrast: Rgb;
  background: Rgb;
  panel: Rgb;
  accentSoftOverPanel: Rgb;
};

const themeBlocks = parseThemeBlocks(css);

/** Reads one token, failing loudly instead of comparing against `undefined`. */
function token(tokens: Map<string, string>, name: string, selector: string): string {
  const value = tokens.get(name);
  if (value === undefined) {
    throw new Error(`${selector} does not define ${name}`);
  }
  return value;
}

/** The colours a contrast check needs, all resolved and composited as the browser would. */
function paletteFor(selector: string): Palette {
  const tokens = themeBlocks.get(selector);
  if (!tokens) {
    throw new Error(`the stylesheet has no ${selector} block`);
  }
  const background = resolveSurface(token(tokens, "--mv-bg", selector));
  const panel = composite(parseRgb(token(tokens, "--mv-panel", selector)), background);
  return {
    accent: resolveSurface(token(tokens, "--mv-accent", selector)),
    accentStrong: resolveSurface(token(tokens, "--mv-accent-strong", selector)),
    accentContrast: resolveSurface(token(tokens, "--mv-accent-contrast", selector)),
    background,
    panel,
    accentSoftOverPanel: composite(parseRgb(token(tokens, "--mv-accent-soft", selector)), panel),
  };
}

type ContrastCheck = {
  label: string;
  measure: (palette: Palette) => number;
};

const CONTRAST_CHECKS: ContrastCheck[] = [
  { label: "accent on accent-contrast", measure: palette => contrastRatio(palette.accent, palette.accentContrast) },
  {
    label: "accent-strong on accent-contrast",
    measure: palette => contrastRatio(palette.accentStrong, palette.accentContrast),
  },
  { label: "accent on the background", measure: palette => contrastRatio(palette.accent, palette.background) },
  { label: "accent on the composited panel", measure: palette => contrastRatio(palette.accent, palette.panel) },
  {
    label: "accent on accent-soft over the composited panel",
    measure: palette => contrastRatio(palette.accent, palette.accentSoftOverPanel),
  },
];

describe("theme palette defined on disk", () => {
  it.each(THEME_BLOCKS)("%s defines the full accent and surface token set", selector => {
    const tokens = themeBlocks.get(selector);

    expect(tokens, `the stylesheet has no ${selector} block`).toBeDefined();
    const missing = REQUIRED_TOKENS.filter(name => !tokens?.has(name));
    expect(missing, `${selector} is missing ${missing.join(", ")}`).toEqual([]);
  });
});

describe.each(THEME_BLOCKS)("%s contrast", selector => {
  it.each(CONTRAST_CHECKS)("keeps $label at AA (>= 4.5:1)", ({ label, measure }) => {
    const ratio = measure(paletteFor(selector));

    expect(
      ratio,
      `${selector}: ${label} measures ${ratio.toFixed(2)}:1, below the AA minimum of ${AA_MINIMUM}:1`,
    ).toBeGreaterThanOrEqual(AA_MINIMUM);
  });
});
