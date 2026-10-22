/**
 * Phishing URL Detector - Security Report Generator
 * Generates structured, professional plain-text audit reports with copy and download capabilities.
 */

import { siteConfig } from "./site.config.js";

/**
 * Builds a formatted plain-text security report string.
 * @param {object} scanData - Complete scan analysis and scoring object
 * @returns {string} Formatted report text
 */
export function generateSecurityReportText(scanData) {
  const { inputUrl, sanitizedUrl, schemeAssumed, analyzedAt, anatomy, scoring } = scanData;
  const dateFormatted = new Date(analyzedAt).toLocaleString();

  const divider = "================================================================================";
  const subDivider = "--------------------------------------------------------------------------------";

  const triggeredList = scoring.triggeredChecks.length > 0
    ? scoring.triggeredChecks.map((c, i) => `  ${i + 1}. [ +${c.points} pts ] ${c.name}\n     Explanation: ${c.explanation}\n     Detail: ${c.detail}`).join("\n\n")
    : "  No suspicious indicators triggered. URL passed all 15 heuristic checks.";

  return `${divider}
                  PHISHING URL DETECTOR - SECURITY AUDIT REPORT
                      Progress Review-II (PBL CSIT Milestone)
${divider}

[ PROJECT & SYSTEM METADATA ]
Project Name          : ${siteConfig.projectName}
Institution           : ${siteConfig.institution.name}
Department            : ${siteConfig.institution.department}
Faculty Guide         : ${siteConfig.guide.name}
Report Timestamp      : ${dateFormatted}
Analysis Type         : 100% Offline Rule-Based Heuristic Evaluation (Zero Network Fetch)

${subDivider}
[ SCANNED URL ]
Input URL             : ${inputUrl}
Normalized URL        : ${sanitizedUrl}${schemeAssumed ? " (Default 'http://' inferred)" : ""}

${subDivider}
[ EXECUTIVE VERDICT ]
SAFETY PERCENTAGE     : ${scoring.safetyPercentage}% SAFE
RISK SCORE            : ${scoring.riskScore} / 100
RISK LEVEL            : ${scoring.riskLevelLabel}
FINAL CLASSIFICATION  : ${scoring.classification}
RULE CONFIDENCE       : ${scoring.ruleConfidence}% (Rule-Coverage & Feature-Density Metric)
SUMMARY               : ${scoring.riskLevelSummary}

${subDivider}
[ RECOMMENDED ACTION ]
${scoring.recommendedAction}

${subDivider}
[ URL ANATOMY BREAKDOWN ]
Protocol              : ${anatomy.protocol}
Host Domain           : ${anatomy.host}
Registered Root Domain: ${anatomy.registeredDomain}
Subdomain             : ${anatomy.subdomain || "(None)"}
Subdomain Count       : ${anatomy.subdomainCount}
Port                  : ${anatomy.port} (Explicit: ${anatomy.explicitPort || "Default"})
Path                  : ${anatomy.pathname || "/"}
Query Parameters      : ${anatomy.search || "(None)"}
Fragment / Hash       : ${anatomy.hash || "(None)"}
Total URL Length      : ${anatomy.totalLength} characters
Host Length           : ${anatomy.hostLength} characters
IP Host Detected      : ${anatomy.isIpHost ? "YES (Numeric IP Literal)" : "NO (Domain Name)"}

${subDivider}
[ TRIGGERED RISK INDICATORS (${scoring.triggeredRulesCount} of ${scoring.totalRulesEvaluated} Checks Triggered) ]
${triggeredList}

${subDivider}
[ EDUCATIONAL DISCLAIMER ]
${siteConfig.educationalDisclaimer}
${siteConfig.safetyScoreNote}
Cyber Safety Helpline : National Cyber Crime Reporting Portal (cybercrime.gov.in) | Helpline: 1930
${divider}
`;
}

/**
 * Copies the text report to the user's system clipboard.
 * @param {string} reportText 
 * @returns {Promise<boolean>}
 */
export async function copyReportToClipboard(reportText) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(reportText);
      return true;
    } else {
      // Fallback for non-https or older context
      const textArea = document.createElement("textarea");
      textArea.value = reportText;
      textArea.style.position = "fixed";
      textArea.style.left = "-999999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand("copy");
      document.body.removeChild(textArea);
      return successful;
    }
  } catch (err) {
    console.error("Clipboard copy failed:", err);
    return false;
  }
}

/**
 * Triggers a browser download of the report as a .txt file.
 * @param {string} reportText 
 * @param {string} domain 
 */
export function downloadReportAsFile(reportText, domain = "url") {
  const cleanDomain = domain.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 30);
  const filename = `security-report-${cleanDomain}-${new Date().toISOString().slice(0, 10)}.txt`;

  const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
