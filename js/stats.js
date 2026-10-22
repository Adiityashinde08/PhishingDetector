/**
 * Phishing URL Detector - Statistics & Detection Insights Engine
 * 
 * Computes all metrics STRICTLY from actual stored scan history in localStorage.
 * No hard-coded, fake, or synthetic numbers.
 */

import { getHistory } from "./history.js";

/**
 * Computes summary statistics from the current scan history.
 * @returns {object} Real calculated metrics
 */
export function calculateStatistics() {
  const history = getHistory();
  const totalScans = history.length;

  if (totalScans === 0) {
    return {
      totalScans: 0,
      safeCount: 0,
      suspiciousCount: 0,
      phishingCount: 0,
      averageRiskScore: 0,
      averageSafetyPercentage: 100,
      lowRiskCount: 0,
      mediumRiskCount: 0,
      highRiskCount: 0,
      detectionInsights: []
    };
  }

  let safeCount = 0;
  let suspiciousCount = 0;
  let phishingCount = 0;
  let lowRiskCount = 0;
  let mediumRiskCount = 0;
  let highRiskCount = 0;

  let totalRiskScore = 0;
  let totalSafetyPercentage = 0;

  // Track frequency of each triggered indicator
  const indicatorCounts = {};

  for (const scan of history) {
    totalRiskScore += Number(scan.riskScore) || 0;
    totalSafetyPercentage += Number(scan.safetyPercentage) || 0;

    // Classification tally
    if (scan.classification === "SAFE") safeCount++;
    else if (scan.classification === "SUSPICIOUS") suspiciousCount++;
    else if (scan.classification === "PHISHING") phishingCount++;

    // Risk level tally
    if (scan.riskLevelKey === "LOW") lowRiskCount++;
    else if (scan.riskLevelKey === "MEDIUM") mediumRiskCount++;
    else if (scan.riskLevelKey === "HIGH") highRiskCount++;

    // Tally triggered checks
    if (Array.isArray(scan.triggeredCheckNames)) {
      for (const checkName of scan.triggeredCheckNames) {
        indicatorCounts[checkName] = (indicatorCounts[checkName] || 0) + 1;
      }
    }
  }

  const averageRiskScore = Math.round(totalRiskScore / totalScans);
  const averageSafetyPercentage = Math.round(totalSafetyPercentage / totalScans);

  // Compute Detection Insights: Ranked list of most frequently triggered indicators
  const detectionInsights = Object.entries(indicatorCounts)
    .map(([name, count]) => ({
      name,
      count,
      percentageOfScans: Math.round((count / totalScans) * 100)
    }))
    .sort((a, b) => b.count - a.count);

  return {
    totalScans,
    safeCount,
    suspiciousCount,
    phishingCount,
    lowRiskCount,
    mediumRiskCount,
    highRiskCount,
    averageRiskScore,
    averageSafetyPercentage,
    detectionInsights
  };
}
