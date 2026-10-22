/**
 * Phishing URL Detector - URL Comparison Engine
 * Compares two URLs side-by-side to highlight how syntactic differences drive risk scores.
 */

import { analyzeUrl } from "./analyzer.js";
import { calculateRiskAndSafety } from "./scorer.js";

/**
 * Compares two URLs and extracts parallel evaluation features.
 * @param {string} urlA 
 * @param {string} urlB 
 * @returns {object} Comparison results
 */
export function compareUrls(urlA, urlB) {
  const analysisA = analyzeUrl(urlA);
  const analysisB = analyzeUrl(urlB);

  const resultA = {
    valid: analysisA.success,
    error: analysisA.error,
    url: urlA,
    sanitizedUrl: analysisA.sanitizedUrl,
    anatomy: analysisA.anatomy,
    scoring: analysisA.success ? calculateRiskAndSafety(analysisA.checks, analysisA.anatomy) : null,
    checks: analysisA.checks
  };

  const resultB = {
    valid: analysisB.success,
    error: analysisB.error,
    url: urlB,
    sanitizedUrl: analysisB.sanitizedUrl,
    anatomy: analysisB.anatomy,
    scoring: analysisB.success ? calculateRiskAndSafety(analysisB.checks, analysisB.anatomy) : null,
    checks: analysisB.checks
  };

  return { resultA, resultB };
}

/**
 * Builds comparison rows matrix for table rendering.
 * @param {object} resultA 
 * @param {object} resultB 
 * @returns {Array<object>}
 */
export function buildComparisonMatrix(resultA, resultB) {
  if (!resultA.valid || !resultB.valid) {
    return [];
  }

  const scA = resultA.scoring;
  const scB = resultB.scoring;
  const anA = resultA.anatomy;
  const anB = resultB.anatomy;

  const findCheck = (checks, id) => checks.find(c => c.id === id);

  return [
    {
      feature: "Safety Percentage",
      valA: `${scA.safetyPercentage}% Safe`,
      valB: `${scB.safetyPercentage}% Safe`,
      statusA: scA.safetyPercentage >= 70 ? "safe" : scA.safetyPercentage >= 40 ? "warning" : "danger",
      statusB: scB.safetyPercentage >= 70 ? "safe" : scB.safetyPercentage >= 40 ? "warning" : "danger",
      higherIsBetter: true
    },
    {
      feature: "Risk Score",
      valA: `${scA.riskScore} / 100`,
      valB: `${scB.riskScore} / 100`,
      statusA: scA.riskScore < 30 ? "safe" : scA.riskScore < 60 ? "warning" : "danger",
      statusB: scB.riskScore < 30 ? "safe" : scB.riskScore < 60 ? "warning" : "danger",
      higherIsBetter: false
    },
    {
      feature: "Risk Level",
      valA: scA.riskLevelLabel,
      valB: scB.riskLevelLabel,
      statusA: scA.riskLevelKey === "LOW" ? "safe" : scA.riskLevelKey === "MEDIUM" ? "warning" : "danger",
      statusB: scB.riskLevelKey === "LOW" ? "safe" : scB.riskLevelKey === "MEDIUM" ? "warning" : "danger"
    },
    {
      feature: "Final Classification",
      valA: scA.classification,
      valB: scB.classification,
      statusA: scA.classification === "SAFE" ? "safe" : scA.classification === "SUSPICIOUS" ? "warning" : "danger",
      statusB: scB.classification === "SAFE" ? "safe" : scB.classification === "SUSPICIOUS" ? "warning" : "danger"
    },
    {
      feature: "HTTPS Transport",
      valA: anA.protocol === "https:" ? "Enabled (HTTPS)" : "Disabled (Plain HTTP)",
      valB: anB.protocol === "https:" ? "Enabled (HTTPS)" : "Disabled (Plain HTTP)",
      statusA: anA.protocol === "https:" ? "safe" : "danger",
      statusB: anB.protocol === "https:" ? "safe" : "danger"
    },
    {
      feature: "Host Type",
      valA: anA.isIpHost ? "Raw IP Address" : "Registered Domain Name",
      valB: anB.isIpHost ? "Raw IP Address" : "Registered Domain Name",
      statusA: anA.isIpHost ? "danger" : "safe",
      statusB: anB.isIpHost ? "danger" : "safe"
    },
    {
      feature: "URL Length",
      valA: `${anA.totalLength} characters`,
      valB: `${anB.totalLength} characters`,
      statusA: anA.totalLength > 75 ? "warning" : "safe",
      statusB: anB.totalLength > 75 ? "warning" : "safe"
    },
    {
      feature: "Subdomain Nesting",
      valA: `${anA.subdomainCount} subdomains`,
      valB: `${anB.subdomainCount} subdomains`,
      statusA: anA.subdomainCount >= 3 ? "warning" : "safe",
      statusB: anB.subdomainCount >= 3 ? "warning" : "safe"
    },
    {
      feature: "Brand Impersonation",
      valA: findCheck(resultA.checks, "RULE_BRAND_IMPERSONATION")?.triggered ? "DETECTED (Spoofing)" : "None Detected",
      valB: findCheck(resultB.checks, "RULE_BRAND_IMPERSONATION")?.triggered ? "DETECTED (Spoofing)" : "None Detected",
      statusA: findCheck(resultA.checks, "RULE_BRAND_IMPERSONATION")?.triggered ? "danger" : "safe",
      statusB: findCheck(resultB.checks, "RULE_BRAND_IMPERSONATION")?.triggered ? "danger" : "safe"
    },
    {
      feature: "Credential / Urgency Keywords",
      valA: findCheck(resultA.checks, "RULE_SUSPICIOUS_KEYWORDS")?.triggered ? "Triggered (Login/Auth)" : "Clean",
      valB: findCheck(resultB.checks, "RULE_SUSPICIOUS_KEYWORDS")?.triggered ? "Triggered (Login/Auth)" : "Clean",
      statusA: findCheck(resultA.checks, "RULE_SUSPICIOUS_KEYWORDS")?.triggered ? "warning" : "safe",
      statusB: findCheck(resultB.checks, "RULE_SUSPICIOUS_KEYWORDS")?.triggered ? "warning" : "safe"
    },
    {
      feature: "Suspicious TLD",
      valA: findCheck(resultA.checks, "RULE_SUSPICIOUS_TLD")?.triggered ? `Triggered (.${anA.tld})` : `Standard (.${anA.tld || "none"})`,
      valB: findCheck(resultB.checks, "RULE_SUSPICIOUS_TLD")?.triggered ? `Triggered (.${anB.tld})` : `Standard (.${anB.tld || "none"})`,
      statusA: findCheck(resultA.checks, "RULE_SUSPICIOUS_TLD")?.triggered ? "warning" : "safe",
      statusB: findCheck(resultB.checks, "RULE_SUSPICIOUS_TLD")?.triggered ? "warning" : "safe"
    },
    {
      feature: "Network Port",
      valA: anA.explicitPort ? `Port :${anA.explicitPort}` : `Standard (${anA.port})`,
      valB: anB.explicitPort ? `Port :${anB.explicitPort}` : `Standard (${anB.port})`,
      statusA: findCheck(resultA.checks, "RULE_UNUSUAL_PORT")?.triggered ? "warning" : "safe",
      statusB: findCheck(resultB.checks, "RULE_UNUSUAL_PORT")?.triggered ? "warning" : "safe"
    },
    {
      feature: "@ Symbol Authority Trick",
      valA: findCheck(resultA.checks, "RULE_AT_SYMBOL")?.triggered ? "Present (@ detected)" : "Absent",
      valB: findCheck(resultB.checks, "RULE_AT_SYMBOL")?.triggered ? "Present (@ detected)" : "Absent",
      statusA: findCheck(resultA.checks, "RULE_AT_SYMBOL")?.triggered ? "danger" : "safe",
      statusB: findCheck(resultB.checks, "RULE_AT_SYMBOL")?.triggered ? "danger" : "safe"
    }
  ];
}
