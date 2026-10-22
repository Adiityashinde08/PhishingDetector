/**
 * Phishing URL Detector - Detection Test Lab
 * 
 * Executes real test suite directly in the browser against analyzer.js and scorer.js.
 * All tests run live, never faked.
 * 
 * Explicitly labeled: "Rule-engine test-suite pass rate" (NOT real-world accuracy).
 */

import { analyzeUrl, validateUrlInput } from "./analyzer.js";
import { calculateRiskAndSafety } from "./scorer.js";

export const TEST_SUITE = [
  {
    id: "TC-01",
    name: "Safe Canonical HTTPS Domain",
    input: "https://www.wikipedia.org",
    expectedDescription: "HTTPS detected, no IP, no keywords, risk score < 30, classification SAFE",
    assert: (res, score) => {
      return res.success &&
        res.anatomy.protocol === "https:" &&
        !res.anatomy.isIpHost &&
        score.riskScore < 30 &&
        score.classification === "SAFE";
    }
  },
  {
    id: "TC-02",
    name: "Empty / Whitespace Input Rejection",
    input: "   ",
    expectedDescription: "Validation fails gracefully with friendly error message",
    assert: (res) => {
      return !res.success && typeof res.error === "string" && res.error.length > 0;
    }
  },
  {
    id: "TC-03",
    name: "URL Without Scheme (Auto-assumption)",
    input: "python.org/downloads",
    expectedDescription: "Analyzer defaults scheme to http:// and informs user without crashing",
    assert: (res, score) => {
      return res.success &&
        res.schemeAssumed === true &&
        res.sanitizedUrl.startsWith("http://") &&
        res.anatomy.host === "python.org";
    }
  },
  {
    id: "TC-04",
    name: "Plain HTTP Flagging",
    input: "http://example.test",
    expectedDescription: "Triggers RULE_NO_HTTPS check",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_NO_HTTPS");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-05",
    name: "Raw IPv4 Address Hostname Detection",
    input: "http://192.168.1.1/admin/login",
    expectedDescription: "Flags RULE_IP_HOST with high severity",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_IP_HOST");
      return res.success && res.anatomy.isIpHost && check && check.triggered === true;
    }
  },
  {
    id: "TC-06",
    name: "RFC 3986 '@' Symbol Spoofing Detection",
    input: "http://paypal.com.account-verify.example.test/login@update",
    expectedDescription: "Flags RULE_AT_SYMBOL authority trick",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_AT_SYMBOL");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-07",
    name: "Excessive URL Character Length",
    input: "https://example.test/" + "a".repeat(100) + "/verify-account-credential-tokens",
    expectedDescription: "Flags RULE_EXCESSIVE_LENGTH when character length > 75",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_EXCESSIVE_LENGTH");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-08",
    name: "Suspicious Credential / Urgency Keywords",
    input: "http://secure-update.example.test/account/verify/login",
    expectedDescription: "Detects multiple keywords (secure, update, account, verify, login)",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_SUSPICIOUS_KEYWORDS");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-09",
    name: "Unusual / Non-Standard Web Port",
    input: "http://example.test:8080/portal",
    expectedDescription: "Flags port 8080 as non-standard (RULE_UNUSUAL_PORT)",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_UNUSUAL_PORT");
      return res.success && res.anatomy.explicitPort === "8080" && check && check.triggered === true;
    }
  },
  {
    id: "TC-10",
    name: "Punycode / Homograph (IDN) Hostname",
    input: "https://xn--gogle-pra.example.test",
    expectedDescription: "Flags RULE_PUNYCODE_HOST for 'xn--' prefix",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_PUNYCODE_HOST");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-11",
    name: "URL Shortener Domain Identification",
    input: "https://bit.ly/3xSampleToken",
    expectedDescription: "Flags RULE_URL_SHORTENER for known shortener domain",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_URL_SHORTENER");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-12",
    name: "High-Abuse Top-Level Domain (TLD)",
    input: "http://free-gift-winner.tk",
    expectedDescription: "Flags RULE_SUSPICIOUS_TLD for .tk domain",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_SUSPICIOUS_TLD");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-13",
    name: "Brand Impersonation in Subdomain",
    input: "http://paypal.com.verify-billing.attacker-domain.test/signin",
    expectedDescription: "Detects PayPal brand impersonation outside official domain",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_BRAND_IMPERSONATION");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-14",
    name: "Embedded Redirection Pattern",
    input: "https://safe-looking.example.test//attacker.test/login",
    expectedDescription: "Flags double slash '//' after scheme (RULE_EMBEDDED_REDIRECT)",
    assert: (res, score) => {
      const check = res.checks.find(c => c.id === "RULE_EMBEDDED_REDIRECT");
      return res.success && check && check.triggered === true;
    }
  },
  {
    id: "TC-15",
    name: "Excessive Character Count Boundary (>2048 Rejection)",
    input: "https://example.test/" + "x".repeat(2050),
    expectedDescription: "Rejects URLs exceeding 2048 RFC limit with friendly validation error",
    assert: (res) => {
      return !res.success && res.error && res.error.includes("2048");
    }
  },
  {
    id: "TC-16",
    name: "Safety Percentage & Risk Score Inversion Formula",
    input: "http://192.168.10.5:8080/secure/login/verify-account.php",
    expectedDescription: "Verifies Safety % = 100 - Risk Score, clamped between 0 and 100",
    assert: (res, score) => {
      return res.success &&
        score.safetyPercentage === (100 - score.riskScore) &&
        score.riskScore >= 60 &&
        score.riskLevelKey === "HIGH";
    }
  }
];

/**
 * Runs all test cases synchronously and records execution metrics.
 * @returns {object} Summary and array of test results
 */
export function runTestSuite() {
  const startTime = performance.now();
  const results = [];
  let passedCount = 0;

  for (const tc of TEST_SUITE) {
    const t0 = performance.now();
    let pass = false;
    let actualDetails = "";
    let executionError = null;

    try {
      const analysis = analyzeUrl(tc.input);
      let scoring = null;
      if (analysis.success) {
        scoring = calculateRiskAndSafety(analysis.checks, analysis.anatomy);
      }

      pass = Boolean(tc.assert(analysis, scoring));
      actualDetails = analysis.success
        ? `Safety: ${scoring.safetyPercentage}%, Risk: ${scoring.riskScore}/100, Level: ${scoring.riskLevelLabel}, Classification: ${scoring.classification}`
        : `Validation caught: "${analysis.error}"`;
    } catch (err) {
      pass = false;
      executionError = err.message;
      actualDetails = `Execution exception: ${err.message}`;
    }

    const t1 = performance.now();
    const durationMs = (t1 - t0).toFixed(2);

    if (pass) passedCount++;

    results.push({
      id: tc.id,
      name: tc.name,
      input: tc.input,
      expected: tc.expectedDescription,
      actual: actualDetails,
      passed: pass,
      durationMs,
      error: executionError
    });
  }

  const totalTime = (performance.now() - startTime).toFixed(1);
  const total = TEST_SUITE.length;
  const failedCount = total - passedCount;
  const passRate = total > 0 ? ((passedCount / total) * 100).toFixed(1) : "0.0";

  return {
    totalTests: total,
    passedCount,
    failedCount,
    passRate,
    totalTimeMs: totalTime,
    results
  };
}
