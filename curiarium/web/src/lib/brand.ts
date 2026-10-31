import type { ResolvedTheme } from "./settings";

/** The lockup that matches each resolved theme. Purple is the brand default. */
export function logoForTheme(theme: ResolvedTheme): string {
  switch (theme) {
    case "neon":
      return "/img/green_theme/Neon_Green_bgrm.png";
    case "purple":
      return "/img/purple_theme/Neon_Purple_logo_bgrm.png";
    case "blue":
      return "/img/blue_theme/Blue_Theme_logo_bgrm.png";
    case "dark":
      return "/img/whitelogo.png";
    default:
      return "/img/blacklogo.png";
  }
}
