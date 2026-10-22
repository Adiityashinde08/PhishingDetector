/**
 * Phishing URL Detector - Controlled Demo Samples
 * All URLs use safe reserved domains (.example.test, .test) or trusted legitimate educational domains.
 * NEVER connects to or fetches these links.
 */

export const sampleUrls = [
  {
    category: "safe",
    badge: "SAFE DEMO",
    label: "Legitimate Encyclopedia",
    url: "https://www.wikipedia.org",
    note: "Demo example, not a real attack. Genuine HTTPS, clean domain, standard structure."
  },
  {
    category: "safe",
    badge: "SAFE DEMO",
    label: "Legitimate Python Portal",
    url: "https://www.python.org/downloads/",
    note: "Demo example, not a real attack. Official programming language repository with HTTPS."
  },
  {
    category: "suspicious",
    badge: "SUSPICIOUS DEMO",
    label: "Unencrypted Bank Mockup",
    url: "http://example-bank-login.example.test/",
    note: "Demo example, not a real site. Uses HTTP without encryption and contains 'login' keyword."
  },
  {
    category: "suspicious",
    badge: "SUSPICIOUS DEMO",
    label: "Verification Prompt Mockup",
    url: "http://secure-update.example.test/account/verify",
    note: "Demo example, not a real site. Combines HTTP with keywords: 'secure', 'update', 'account', 'verify'."
  },
  {
    category: "phishing",
    badge: "PHISHING DEMO",
    label: "Raw IP & Custom Port Mockup",
    url: "http://192.168.10.5:8080/secure/login/verify-account.php",
    note: "Demo example, RFC 1918 private IP. Triggers: IP as host, unusual port :8080, HTTP, and login keywords."
  },
  {
    category: "phishing",
    badge: "PHISHING DEMO",
    label: "Brand Impersonation & @ Symbol Mockup",
    url: "http://paypal.com.account-verify.example.test/login@update",
    note: "Demo example, not a real site. Triggers: Brand spoofing (PayPal in subdomain), @ symbol trick, HTTP, keywords."
  }
];

export const sampleComparisonPairs = [
  {
    title: "Legitimate Portal vs Brand Impersonation Demo",
    urlA: "https://www.wikipedia.org",
    labelA: "Wikipedia (Official)",
    urlB: "http://paypal.com.account-verify.example.test/login@update",
    labelB: "Phishing Demo (Brand Spoof + @ + HTTP)"
  },
  {
    title: "Official Download vs Raw IP & Custom Port Demo",
    urlA: "https://www.python.org/downloads/",
    labelA: "Python.org (Official)",
    urlB: "http://192.168.10.5:8080/secure/login/verify-account.php",
    labelB: "Phishing Demo (IP + Port 8080 + Login)"
  }
];
