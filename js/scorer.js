/**
 * Phishing URL Detector - Scoring & Classification Engine
 * 
 * Computes:
 * 1. Total Risk Score (0 - 100)
 * 2. Safety Percentage (100 - Risk Score, clamped to 0 - 100)
 * 3. Risk Level (LOW, MEDIUM, HIGH)
 * 4. Final Classification (SAFE, SUSPICIOUS, PHISHING)
 * 5. Rule Confidence (transparent evaluation metrics, strictly non-AI)
 * 6. Tailored Recommended Action
 */

import { siteConfig } from "./site.config.js";

/**
 * Computes comprehensive scoring metrics from an array of evaluated checks.
 * @param {Array<object>} checks - The 15 evaluated security checks
 * @param {object} anatomy - URL anatomical structure
 * @returns {object} Calculated scores, classification, confidence, and recommendations
 */
export function calculateRiskAndSafety(checks, anatomy = {}) {
  // 1. Calculate raw Risk Score (sum of triggered points)
  let rawRiskScore = 0;
  const triggeredChecks = [];
  const passedChecks = [];

  for (const check of checks) {
    if (check.triggered) {
      rawRiskScore += Number(check.points) || 0;
      triggeredChecks.push(check);
    } else {
      passedChecks.push(check);
    }
  }

  // Cap Risk Score between 0 and 100
  const riskScore = Math.max(0, Math.min(100, Math.round(rawRiskScore)));

  // 2. Calculate Safety Percentage
  // Transparent inverse relationship: Safety = 100 - Risk Score
  const safetyPercentage = Math.max(0, Math.min(100, 100 - riskScore));

  // 3. Determine Risk Level based on configurable safety thresholds
  // 70 - 100% Safe -> LOW
  // 40 - 69% Safe  -> MEDIUM
  // 0 - 39% Safe   -> HIGH
  const { thresholds, riskLevels } = siteConfig;
  let riskLevel;

  if (safetyPercentage >= thresholds.safety.lowRiskMin) {
    riskLevel = riskLevels.LOW;
  } else if (safetyPercentage >= thresholds.safety.mediumRiskMin) {
    riskLevel = riskLevels.MEDIUM;
  } else {
    riskLevel = riskLevels.HIGH;
  }

  // 4. Determine Final Classification based on Risk Score
  // 0 - 29 -> SAFE
  // 30 - 59 -> SUSPICIOUS
  // 60 - 100 -> PHISHING
  let classification = "SAFE";
  let classificationBadgeClass = "badge-safe";

  if (riskScore >= thresholds.risk.phishingMin) {
    classification = "PHISHING";
    classificationBadgeClass = "badge-phishing";
  } else if (riskScore > thresholds.risk.safeMax) {
    classification = "SUSPICIOUS";
    classificationBadgeClass = "badge-suspicious";
  } else {
    classification = "SAFE";
    classificationBadgeClass = "badge-safe";
  }

  // 5. Calculate Rule Confidence (Strictly Heuristic / Rule-based)
  // Transparent formula: Evaluates rule agreement, signal strength, and structural completeness.
  // Never claims to be AI or ML confidence.
  const totalRules = checks.length;
  const triggeredCount = triggeredChecks.length;

  let ruleConfidence;
  if (triggeredCount === 0) {
    // Zero indicators triggered out of all 15 rules -> High rule confidence that no defined pattern exists
    ruleConfidence = 92;
  } else if (triggeredCount >= 4 || riskScore >= 70) {
    // Multiple corroborating indicators triggered -> High rule confidence in classification
    ruleConfidence = Math.min(98, 85 + (triggeredCount * 2));
  } else if (riskScore >= 30) {
    // Moderate ambiguity or border score
    ruleConfidence = 78;
  } else {
    ruleConfidence = 84;
  }

  // Sort triggered checks by points descending for explainability breakdown
  triggeredChecks.sort((a, b) => b.points - a.points);

  // 6. Generate Contextual Recommended Action
  let recommendedAction = riskLevel.recommendation;
  const specificAdvice = [];

  if (triggeredChecks.some(c => c.id === "RULE_IP_HOST")) {
    specificAdvice.push("Never authenticate or submit data to a raw IP address host.");
  }
  if (triggeredChecks.some(c => c.id === "RULE_BRAND_IMPERSONATION")) {
    specificAdvice.push("Potential brand credential spoofing detected. Do not enter login passwords or OTPs.");
  }
  if (triggeredChecks.some(c => c.id === "RULE_NO_HTTPS")) {
    specificAdvice.push("The connection is unencrypted. Any submitted form data can be intercepted by network eavesdroppers.");
  }
  if (triggeredChecks.some(c => c.id === "RULE_AT_SYMBOL")) {
    specificAdvice.push("The '@' symbol alters URL routing. Check the actual host destination carefully.");
  }

  if (specificAdvice.length > 0) {
    recommendedAction = `${recommendedAction} Key precautions: ${specificAdvice.join(" ")}`;
  }

  return {
    riskScore,
    safetyPercentage,
    riskLevelKey: riskLevel.key,
    riskLevelLabel: riskLevel.label,
    riskLevelSummary: riskLevel.summary,
    riskColor: riskLevel.color,
    badgeClass: riskLevel.badgeClass,
    classification,
    classificationBadgeClass,
    ruleConfidence,
    triggeredChecks,
    passedChecks,
    totalRulesEvaluated: totalRules,
    triggeredRulesCount: triggeredCount,
    recommendedAction
  };
}
