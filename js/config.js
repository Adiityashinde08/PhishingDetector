/**
 * Phishing URL Detector - Detection Rules & Heuristics Configuration
 * Transparent weights, thresholds, keywords, and rule definitions.
 * Modify weights or lists here to tune the detection engine.
 */

export const detectorConfig = {
  // Configurable Rule Weights (points added to Risk Score when triggered)
  // Scores are bounded to 100 max.
  weights: {
    ip_host: 25,              // Using raw IP address instead of domain name
    brand_impersonation: 22,  // Brand name in subdomain/path on third-party domain
    at_symbol: 20,            // Presence of '@' in URL (RFC 3986 userinfo credential trick)
    no_https: 15,             // Plain HTTP protocol or insecure scheme
    suspicious_keywords: 14,  // Phishing/credential harvesting keywords (login, verify, etc.)
    unusual_port: 15,         // Non-standard web ports (e.g. 8080, 8888, 81)
    suspicious_tld: 15,       // Free or heavily abused top-level domains
    url_shortener: 12,        // Obfuscation via URL shortener service
    punycode_host: 16,        // IDN / Punycode (xn--) or non-ASCII characters
    excessive_length: 10,     // Total URL character count exceeding threshold
    excessive_subdomains: 12, // More than normal subdomains (domain nesting)
    excessive_hyphens: 10,    // High frequency of hyphens in host/path
    embedded_redirect: 14,    // Suspicious redirect params (//, redirect=, url=)
    heavy_encoding: 10,       // Excessive percent-encoding (%xx)
    high_digit_ratio: 10      // Unusually high ratio of numbers in host
  },

  // Numerical Thresholds for Rule Evaluation
  thresholds: {
    maxUrlLengthNormal: 75,          // URLs > 75 chars trigger excessive length warning
    maxUrlLengthExtreme: 140,        // Extreme length threshold
    maxSubdomains: 3,                // Subdomains >= 3 trigger excessive subdomains
    maxHostHyphens: 2,               // Hyphens in domain >= 2 trigger warning
    maxPathHyphens: 4,               // Hyphens in path >= 4 trigger warning
    maxDigitRatio: 0.25,             // Digits make up > 25% of hostname characters
    maxEncodedCharsCount: 3,         // More than 3 percent-encoded patterns
    maxDotsCount: 4                  // More than 4 dots in entire URL
  },

  // Sensitive & Phishing-Associated Keywords
  // Attackers use these to create urgency or mimic authentication flows
  suspiciousKeywords: [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "verified",
    "account", "update", "security", "secure",
    "banking", "authenticate", "auth",
    "confirm", "confirmation", "password",
    "credential", "recover", "recovery",
    "wallet", "billing", "invoice", "payment",
    "ebayisapi", "webscr", "cmd=_login-run",
    "re-activate", "suspend", "suspended",
    "support-desk", "service-update", "id-verify"
  ],

  // Targeted Brands commonly impersonated by phishing kits
  // If these names appear in subdomain or path while root domain is different, flag brand impersonation
  targetBrands: [
    { name: "paypal", officialDomains: ["paypal.com", "paypal.me"] },
    { name: "google", officialDomains: ["google.com", "google.co.in", "accounts.google.com"] },
    { name: "apple", officialDomains: ["apple.com", "icloud.com"] },
    { name: "microsoft", officialDomains: ["microsoft.com", "live.com", "office.com", "outlook.com"] },
    { name: "amazon", officialDomains: ["amazon.com", "amazon.in", "amazon.co.uk"] },
    { name: "netflix", officialDomains: ["netflix.com"] },
    { name: "facebook", officialDomains: ["facebook.com", "fb.com"] },
    { name: "instagram", officialDomains: ["instagram.com"] },
    { name: "sbi", officialDomains: ["onlinesbi.sbi", "sbi.co.in"] },
    { name: "hdfc", officialDomains: ["hdfcbank.com"] },
    { name: "icici", officialDomains: ["icicibank.com"] },
    { name: "chase", officialDomains: ["chase.com"] },
    { name: "wellsfargo", officialDomains: ["wellsfargo.com"] },
    { name: "binance", officialDomains: ["binance.com"] },
    { name: "coinbase", officialDomains: ["coinbase.com"] },
    { name: "meta", officialDomains: ["meta.com"] },
    { name: "dropbox", officialDomains: ["dropbox.com"] },
    { name: "github", officialDomains: ["github.com"] }
  ],

  // Top-Level Domains (TLDs) historically known for high abuse rates in security literature
  suspiciousTlds: [
    "tk", "ml", "ga", "cf", "gq",      // Freenom free domains (legacy abuse vectors)
    "top", "xyz", "work", "click", "buzz",
    "fit", "loan", "cam", "country", "stream",
    "racing", "surf", "casa", "icu", "rest", "bar",
    "monster", "hair", "skin", "quest"
  ],

  // Known URL Shortening Domains
  urlShorteners: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "rebrand.ly", "bl.ink",
    "v.gd", "soo.gd", "trib.al"
  ],

  // Standard Web Ports (Traffic on non-standard ports is suspicious)
  standardPorts: ["80", "443", ""],

  // Suspicious open redirect query parameters
  redirectParameters: [
    "url", "redirect", "redir", "next", "dest", "destination",
    "target", "rdir", "view", "link", "out", "goto"
  ],

  // Active / Enabled Rules in Engine
  enabledRules: [
    "RULE_NO_HTTPS",
    "RULE_IP_HOST",
    "RULE_AT_SYMBOL",
    "RULE_EXCESSIVE_LENGTH",
    "RULE_EXCESSIVE_SUBDOMAINS",
    "RULE_EXCESSIVE_HYPHENS",
    "RULE_SUSPICIOUS_KEYWORDS",
    "RULE_UNUSUAL_PORT",
    "RULE_PUNYCODE_HOST",
    "RULE_URL_SHORTENER",
    "RULE_SUSPICIOUS_TLD",
    "RULE_BRAND_IMPERSONATION",
    "RULE_EMBEDDED_REDIRECT",
    "RULE_HEAVY_ENCODING",
    "RULE_HIGH_DIGIT_RATIO"
  ]
};
