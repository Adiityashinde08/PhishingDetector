/**
 * Phishing URL Detector - Theme Manager
 * Supports: Cyber Cyan (default dark), Matrix Green, Neon Purple, and Light Clean.
 * Persists selection in localStorage.
 */

import { siteConfig } from "./site.config.js";

const THEMES = [
  { id: "cyber-cyan", name: "Cyber Cyan (Default Dark)", icon: "⚡" },
  { id: "matrix-green", name: "Matrix Green", icon: "🟢" },
  { id: "neon-purple", name: "Neon Purple", icon: "🟣" },
  { id: "light-clean", name: "Light Clean", icon: "☀️" }
];

export function initTheme() {
  const storedTheme = localStorage.getItem(siteConfig.storage.themeKey) || "cyber-cyan";
  setTheme(storedTheme);
}

export function setTheme(themeId) {
  const validTheme = THEMES.some(t => t.id === themeId) ? themeId : "cyber-cyan";
  document.documentElement.setAttribute("data-theme", validTheme);
  try {
    localStorage.setItem(siteConfig.storage.themeKey, validTheme);
  } catch (e) {
    console.warn("Unable to save theme to localStorage:", e);
  }

  // Update active state in UI selectors if present
  const themeSelect = document.getElementById("theme-select");
  if (themeSelect) {
    themeSelect.value = validTheme;
  }
}

export function getAvailableThemes() {
  return THEMES;
}

export function getCurrentTheme() {
  return document.documentElement.getAttribute("data-theme") || "cyber-cyan";
}
