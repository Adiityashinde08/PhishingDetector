/**
 * Phishing URL Detector - Scan History Manager
 * Uses localStorage only (storage key: pud_history_v1)
 * Provides add, list, delete, clear, search/filter, and real CSV export.
 */

import { siteConfig } from "./site.config.js";

const STORAGE_KEY = siteConfig.storage.historyKey || "pud_history_v1";
const MAX_ITEMS = siteConfig.storage.maxHistoryItems || 50;

/**
 * Retrieves the full scan history array from localStorage.
 * @returns {Array<object>}
 */
export function getHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error("Failed to read history from localStorage:", err);
    return [];
  }
}

/**
 * Saves a new scan record to history.
 * @param {object} scanData - Complete analysis and scoring object
 * @returns {object} The newly created record
 */
export function saveScan(scanData) {
  const history = getHistory();
  const record = {
    id: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
    url: scanData.inputUrl,
    sanitizedUrl: scanData.sanitizedUrl,
    analyzedAt: scanData.analyzedAt || new Date().toISOString(),
    safetyPercentage: scanData.scoring.safetyPercentage,
    riskScore: scanData.scoring.riskScore,
    riskLevelKey: scanData.scoring.riskLevelKey,
    riskLevelLabel: scanData.scoring.riskLevelLabel,
    classification: scanData.scoring.classification,
    badgeClass: scanData.scoring.badgeClass,
    triggeredChecksCount: scanData.scoring.triggeredRulesCount,
    triggeredCheckIds: scanData.scoring.triggeredChecks.map(c => c.id),
    triggeredCheckNames: scanData.scoring.triggeredChecks.map(c => c.name),
    host: scanData.anatomy.host,
    protocol: scanData.anatomy.protocol
  };

  // Prepend to list (most recent first)
  history.unshift(record);

  // Enforce maximum history capacity
  if (history.length > MAX_ITEMS) {
    history.length = MAX_ITEMS;
  }

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch (err) {
    console.error("Failed to save history to localStorage:", err);
  }

  return record;
}

/**
 * Deletes an individual scan record by ID.
 * @param {string} id 
 * @returns {Array<object>} Updated history
 */
export function deleteScan(id) {
  let history = getHistory();
  history = history.filter(item => item.id !== id);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch (err) {
    console.error("Failed to update history after delete:", err);
  }
  return history;
}

/**
 * Clears all scan history from localStorage.
 */
export function clearHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.error("Failed to clear history:", err);
  }
}

/**
 * Filters history by search query (URL/host) and risk level.
 * @param {string} query 
 * @param {string} riskFilter - "ALL" | "LOW" | "MEDIUM" | "HIGH"
 * @returns {Array<object>}
 */
export function filterHistory(query = "", riskFilter = "ALL") {
  const history = getHistory();
  const q = query.trim().toLowerCase();

  return history.filter(item => {
    const matchesQuery = !q || item.url.toLowerCase().includes(q) || item.host.toLowerCase().includes(q);
    const matchesRisk = riskFilter === "ALL" || item.riskLevelKey === riskFilter;
    return matchesQuery && matchesRisk;
  });
}

/**
 * Exports the history as a downloadable CSV file.
 * Returns CSV string and triggers browser file download.
 */
export function exportHistoryAsCsv() {
  const history = getHistory();
  if (history.length === 0) {
    return { success: false, message: "History is empty. Scan some URLs before exporting." };
  }

  const headers = [
    "Scan ID",
    "Analyzed At",
    "URL",
    "Safety Percentage (%)",
    "Risk Score (/100)",
    "Risk Level",
    "Classification",
    "Triggered Indicators Count",
    "Triggered Checks"
  ];

  const escapeCsv = (str) => `"${String(str || '').replace(/"/g, '""')}"`;

  const rows = history.map(item => [
    escapeCsv(item.id),
    escapeCsv(new Date(item.analyzedAt).toLocaleString()),
    escapeCsv(item.url),
    item.safetyPercentage,
    item.riskScore,
    escapeCsv(item.riskLevelLabel),
    escapeCsv(item.classification),
    item.triggeredChecksCount,
    escapeCsv(item.triggeredCheckNames.join("; "))
  ]);

  const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\r\n");

  // Trigger client-side download
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-scan-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  return { success: true, count: history.length };
}
