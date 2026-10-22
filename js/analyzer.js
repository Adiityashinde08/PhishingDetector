/**
 * Phishing URL Detector - Offline URL Analysis Engine
 * 
 * IMPORTANT: This module performs 100% OFFLINE, rule-based heuristic string analysis.
 * It NEVER fetches, pings, resolves DNS, or connects to any URL.
 */

import { detectorConfig } from "./config.js";

/**
 * Validates input string before parsing.
 * @param {string} rawInput 
 * @returns {{ valid: boolean, error?: string, sanitizedUrl?: string, schemeAssumed?: boolean }}
 */
export function validateUrlInput(rawInput) {
  if (!rawInput || typeof rawInput !== "string") {
    return { valid: false, error: "Please enter a URL to scan." };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: "URL input cannot be blank or whitespace." };
  }

  if (trimmed.length > 2048) {
    return {
      valid: false,
      error: `URL exceeds maximum allowable length of 2048 characters (got ${trimmed.length}). RFC 7230 limits exceeded.`
    };
  }

  // Check if scheme exists (e.g., https://, http://, ftp://)
  let sanitized = trimmed;
  let schemeAssumed = false;

  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//i.test(sanitized)) {
    // No scheme provided. Assume http:// for analysis and inform user.
    sanitized = `http://${sanitized}`;
    schemeAssumed = true;
  }

  return { valid: true, sanitizedUrl: sanitized, schemeAssumed };
}

/**
 * Parses a sanitized URL string into structural anatomical components.
 * @param {string} urlString 
 * @returns {object} URL anatomy breakdown
 */
export function parseUrlAnatomy(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch (err) {
    throw new Error(`Invalid URL structure: Unable to parse "${urlString}". Ensure the format is valid.`);
  }

  const host = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();
  const port = parsed.port || (protocol === "https:" ? "443" : protocol === "http:" ? "80" : "");
  const explicitPort = parsed.port;
  const pathname = parsed.pathname;
  const search = parsed.search;
  const hash = parsed.hash;

  // Split host into subdomains and domain
  // IPv4 / IPv6 check
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
  const isIpv6 = /^\[?[a-fA-F0-9:]+\]?$/.test(host) && host.includes(":");

  let subdomain = "";
  let registeredDomain = host;
  let domainParts = [];
  let subdomainCount = 0;

  if (!isIpv4 && !isIpv6) {
    domainParts = host.split(".").filter(Boolean);
    if (domainParts.length > 2) {
      // Check for compound TLDs like co.uk, com.au, co.in
      const lastTwo = domainParts.slice(-2).join(".");
      const compoundTlds = ["co.uk", "co.in", "com.au", "gov.in", "edu.in", "org.uk", "co.jp"];
      if (compoundTlds.includes(lastTwo) && domainParts.length > 3) {
        registeredDomain = domainParts.slice(-3).join(".");
        subdomain = domainParts.slice(0, -3).join(".");
        subdomainCount = domainParts.length - 3;
      } else {
        registeredDomain = domainParts.slice(-2).join(".");
        subdomain = domainParts.slice(0, -2).join(".");
        subdomainCount = domainParts.length - 2;
      }
    } else {
      registeredDomain = host;
      subdomain = "";
      subdomainCount = 0;
    }
  }

  // TLD extraction
  let tld = "";
  if (!isIpv4 && !isIpv6 && domainParts.length > 1) {
    tld = domainParts[domainParts.length - 1];
  }

  return {
    rawUrl: urlString,
    protocol,
    host,
    registeredDomain,
    subdomain,
    subdomainCount,
    port,
    explicitPort,
    pathname,
    search,
    hash,
    tld,
    isIpv4,
    isIpv6,
    isIpHost: isIpv4 || isIpv6,
    totalLength: urlString.length,
    hostLength: host.length,
    pathLength: pathname.length,
    queryLength: search.length
  };
}

/**
 * Executes all 15 heuristic security checks on the parsed anatomy.
 * @param {object} anatomy 
 * @param {boolean} schemeAssumed 
 * @returns {Array<object>} Evaluated security checks
 */
export function runSecurityChecks(anatomy, schemeAssumed = false) {
  const { weights, thresholds, suspiciousKeywords, targetBrands, suspiciousTlds, urlShorteners, standardPorts, redirectParameters } = detectorConfig;
  const checks = [];

  const raw = anatomy.rawUrl;
  const host = anatomy.host;
  const path = anatomy.pathname;
  const search = anatomy.search;
  const fullPathAndQuery = path + search;

  // -------------------------------------------------------------
  // Check 1: No HTTPS (Insecure Plaintext or Unknown Protocol)
  // -------------------------------------------------------------
  const isHttps = anatomy.protocol === "https:";
  checks.push({
    id: "RULE_NO_HTTPS",
    name: "No HTTPS Protocol",
    triggered: !isHttps,
    points: !isHttps ? weights.no_https : 0,
    severity: "MEDIUM",
    explanation: !isHttps
      ? "URL uses insecure plain HTTP. Data sent over HTTP is unencrypted and vulnerable to eavesdropping and interception."
      : "URL specifies HTTPS protocol with transport-layer encryption.",
    detail: schemeAssumed
      ? `Protocol: ${anatomy.protocol} (Scheme was omitted by user; default HTTP assumed)`
      : `Protocol: ${anatomy.protocol} ${isHttps ? "(Secure encrypted)" : "(Insecure unencrypted)"}`
  });

  // -------------------------------------------------------------
  // Check 2: IP Address as Hostname
  // -------------------------------------------------------------
  checks.push({
    id: "RULE_IP_HOST",
    name: "IP Address as Hostname",
    triggered: anatomy.isIpHost,
    points: anatomy.isIpHost ? weights.ip_host : 0,
    severity: "HIGH",
    explanation: anatomy.isIpHost
      ? "Using a raw numeric IP address instead of a registered domain is a classic phishing technique to evade domain reputation filters."
      : "Hostname is a structured domain name rather than a raw IP literal.",
    detail: anatomy.isIpHost
      ? `Host literal identified: "${host}" (${anatomy.isIpv4 ? "IPv4" : "IPv6"})`
      : `Host domain: "${host}"`
  });

  // -------------------------------------------------------------
  // Check 3: RFC 3986 '@' Symbol in URL Authority
  // -------------------------------------------------------------
  const hasAtSymbol = raw.includes("@");
  checks.push({
    id: "RULE_AT_SYMBOL",
    name: "@ Symbol in Authority (Userinfo Spoofing)",
    triggered: hasAtSymbol,
    points: hasAtSymbol ? weights.at_symbol : 0,
    severity: "HIGH",
    explanation: hasAtSymbol
      ? "In URL standards, the '@' symbol precedes user credentials. Browsers ignore everything before '@' for host routing, misleading victims."
      : "No '@' character found in URL string.",
    detail: hasAtSymbol
      ? `Found '@' symbol at index ${raw.indexOf("@")}. Browsers route to what comes AFTER '@'.`
      : "Standard URL authority formatting without userinfo trickery."
  });

  // -------------------------------------------------------------
  // Check 4: Excessive URL Character Length
  // -------------------------------------------------------------
  const isExcessiveLength = raw.length > thresholds.maxUrlLengthNormal;
  checks.push({
    id: "RULE_EXCESSIVE_LENGTH",
    name: "Excessive URL Character Length",
    triggered: isExcessiveLength,
    points: isExcessiveLength ? weights.excessive_length : 0,
    severity: "LOW",
    explanation: isExcessiveLength
      ? `URL length (${raw.length} chars) exceeds normal threshold (${thresholds.maxUrlLengthNormal}). Phishers often inflate URLs to hide target domains off-screen.`
      : `URL length is within standard compact limits (${raw.length} chars).`,
    detail: `Character count: ${raw.length} (Normal threshold: <= ${thresholds.maxUrlLengthNormal})`
  });

  // -------------------------------------------------------------
  // Check 5: Excessive Subdomains / Dot Count
  // -------------------------------------------------------------
  const dotCountInHost = (host.match(/\./g) || []).length;
  const isExcessiveSubdomains = !anatomy.isIpHost && (anatomy.subdomainCount >= thresholds.maxSubdomains || dotCountInHost >= thresholds.maxDotsCount);
  checks.push({
    id: "RULE_EXCESSIVE_SUBDOMAINS",
    name: "Excessive Subdomains / Nested Dots",
    triggered: isExcessiveSubdomains,
    points: isExcessiveSubdomains ? weights.excessive_subdomains : 0,
    severity: "MEDIUM",
    explanation: isExcessiveSubdomains
      ? `Domain contains ${anatomy.subdomainCount} subdomains (${dotCountInHost} dots). Attackers nest multiple subdomains to mimic legitimate brand names.`
      : "Domain hierarchy depth is within normal limits.",
    detail: `Subdomains count: ${anatomy.subdomainCount} | Host dots: ${dotCountInHost} | Subdomain: "${anatomy.subdomain || 'none'}"`
  });

  // -------------------------------------------------------------
  // Check 6: Excessive Hyphens in Host or Path
  // -------------------------------------------------------------
  const hostHyphens = (host.match(/-/g) || []).length;
  const pathHyphens = (path.match(/-/g) || []).length;
  const isExcessiveHyphens = hostHyphens >= thresholds.maxHostHyphens || pathHyphens >= thresholds.maxPathHyphens;
  checks.push({
    id: "RULE_EXCESSIVE_HYPHENS",
    name: "Excessive Hyphens in Domain/Path",
    triggered: isExcessiveHyphens,
    points: isExcessiveHyphens ? weights.excessive_hyphens : 0,
    severity: "LOW",
    explanation: isExcessiveHyphens
      ? "Frequent hyphens are often used in typosquatting or fake domain names (e.g. 'paypal-secure-update')."
      : "Hyphen usage is minimal and within legitimate parameters.",
    detail: `Hyphens in host: ${hostHyphens} (max ${thresholds.maxHostHyphens}) | Hyphens in path: ${pathHyphens}`
  });

  // -------------------------------------------------------------
  // Check 7: Suspicious Phishing Keywords
  // -------------------------------------------------------------
  const foundKeywords = [];
  const lowerUrl = raw.toLowerCase();
  for (const kw of suspiciousKeywords) {
    if (lowerUrl.includes(kw)) {
      foundKeywords.push(kw);
    }
  }
  const hasSuspiciousKeywords = foundKeywords.length > 0;
  checks.push({
    id: "RULE_SUSPICIOUS_KEYWORDS",
    name: "Suspicious Credential / Urgency Keywords",
    triggered: hasSuspiciousKeywords,
    points: hasSuspiciousKeywords ? weights.suspicious_keywords : 0,
    severity: "MEDIUM",
    explanation: hasSuspiciousKeywords
      ? `Detected ${foundKeywords.length} security/authentication keyword(s): [${foundKeywords.slice(0, 5).join(", ")}]. Commonly used to lure users into submitting credentials.`
      : "No sensitive credential-harvesting keywords found in URL.",
    detail: hasSuspiciousKeywords
      ? `Matched tokens: ${foundKeywords.join(", ")}`
      : "Keyword scan clean."
  });

  // -------------------------------------------------------------
  // Check 8: Unusual / Non-Standard Web Port
  // -------------------------------------------------------------
  const explicitPort = anatomy.explicitPort;
  const isUnusualPort = Boolean(explicitPort && !standardPorts.includes(explicitPort));
  checks.push({
    id: "RULE_UNUSUAL_PORT",
    name: "Unusual / Non-Standard Network Port",
    triggered: isUnusualPort,
    points: isUnusualPort ? weights.unusual_port : 0,
    severity: "MEDIUM",
    explanation: isUnusualPort
      ? `URL explicitly requests port :${explicitPort}. Legitimate public web applications typically run on standard ports 80 (HTTP) or 443 (HTTPS).`
      : "URL utilizes standard web ports (80 / 443).",
    detail: explicitPort ? `Custom port designated: :${explicitPort}` : `Default port inferred: :${anatomy.port}`
  });

  // -------------------------------------------------------------
  // Check 9: Punycode / Homograph (IDN) Attack Pattern
  // -------------------------------------------------------------
  const hasPunycode = host.includes("xn--") || /[^\u0000-\u007F]/.test(raw);
  checks.push({
    id: "RULE_PUNYCODE_HOST",
    name: "Punycode / Homograph (IDN) Obfuscation",
    triggered: hasPunycode,
    points: hasPunycode ? weights.punycode_host : 0,
    severity: "HIGH",
    explanation: hasPunycode
      ? "Host contains 'xn--' Punycode prefix or non-ASCII characters. Often used in homograph attacks where Cyrillic or Greek letters mimic Latin characters (e.g. 'google.com' with Cyrillic 'о')."
      : "All characters in hostname are standard ASCII Latin characters.",
    detail: hasPunycode
      ? `Host '${host}' contains internationalized domain prefixes or multi-byte glyphs.`
      : "Clean standard ASCII encoding."
  });

  // -------------------------------------------------------------
  // Check 10: URL Shortener Domain
  // -------------------------------------------------------------
  const isShortener = urlShorteners.some(shortener => host === shortener || host.endsWith(`.${shortener}`));
  checks.push({
    id: "RULE_URL_SHORTENER",
    name: "URL Shortener Service Detected",
    triggered: isShortener,
    points: isShortener ? weights.url_shortener : 0,
    severity: "MEDIUM",
    explanation: isShortener
      ? `Domain is a known URL shortening provider ('${host}'). Shorteners obscure the true destination hostname, preventing users from seeing where they will land.`
      : "Domain is not a recognized URL shortener service.",
    detail: isShortener ? `Matches known shortener registry: ${host}` : "Direct destination host specified."
  });

  // -------------------------------------------------------------
  // Check 11: Suspicious / High-Abuse Top-Level Domain (TLD)
  // -------------------------------------------------------------
  const hasSuspiciousTld = Boolean(anatomy.tld && suspiciousTlds.includes(anatomy.tld));
  checks.push({
    id: "RULE_SUSPICIOUS_TLD",
    name: "High-Abuse Top-Level Domain (TLD)",
    triggered: hasSuspiciousTld,
    points: hasSuspiciousTld ? weights.suspicious_tld : 0,
    severity: "MEDIUM",
    explanation: hasSuspiciousTld
      ? `The TLD '.${anatomy.tld}' has documented high rates of phishing registration due to low cost or lax verification policies.`
      : "The domain uses a standard or reputable top-level domain.",
    detail: `TLD detected: .${anatomy.tld || "none"} (Suspicious match: ${hasSuspiciousTld ? "YES" : "NO"})`
  });

  // -------------------------------------------------------------
  // Check 12: Brand Impersonation in Subdomain / Path
  // -------------------------------------------------------------
  let brandImpersonated = null;
  for (const brand of targetBrands) {
    const brandName = brand.name.toLowerCase();
    const inSubdomain = anatomy.subdomain.toLowerCase().includes(brandName);
    const inPath = path.toLowerCase().includes(brandName);
    const inHost = host.toLowerCase().includes(brandName);

    // Is the root registered domain an official domain for this brand?
    const isOfficialDomain = brand.officialDomains.some(off => host === off || host.endsWith(`.${off}`));

    if ((inSubdomain || inPath || inHost) && !isOfficialDomain) {
      brandImpersonated = { brand: brandName, inSubdomain, inPath, inHost };
      break;
    }
  }
  const isBrandSpoof = brandImpersonated !== null;
  checks.push({
    id: "RULE_BRAND_IMPERSONATION",
    name: "Brand Impersonation / Spoofing",
    triggered: isBrandSpoof,
    points: isBrandSpoof ? weights.brand_impersonation : 0,
    severity: "HIGH",
    explanation: isBrandSpoof
      ? `The brand name '${brandImpersonated.brand.toUpperCase()}' appears in the ${brandImpersonated.inSubdomain ? 'subdomain' : brandImpersonated.inHost ? 'domain' : 'path'}, but the registered root domain is NOT an official domain for this brand.`
      : "No known corporate or banking brand impersonation detected in subdomain or path.",
    detail: isBrandSpoof
      ? `Detected brand token '${brandImpersonated.brand}' on unauthorized host '${host}'`
      : "Domain ownership alignment verified for known targets."
  });

  // -------------------------------------------------------------
  // Check 13: Embedded Redirect Patterns
  // -------------------------------------------------------------
  let hasEmbeddedRedirect = false;
  let redirectDetail = "No embedded redirection signatures detected.";

  // Pattern: '//' appearing after the initial protocol (e.g. https://legit.com//evil.com)
  const afterScheme = raw.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//, "");
  if (afterScheme.includes("//")) {
    hasEmbeddedRedirect = true;
    redirectDetail = "Multiple consecutive slashes '//' found after scheme, often used to bypass path filters.";
  } else {
    // Check for open redirect query parameters containing http/https
    for (const param of redirectParameters) {
      const regex = new RegExp(`[?&]${param}=https?%3A%2F%2F|[?&]${param}=https?://`, "i");
      if (regex.test(search)) {
        hasEmbeddedRedirect = true;
        redirectDetail = `Found open redirect parameter '?${param}=' containing secondary URL.`;
        break;
      }
    }
  }

  checks.push({
    id: "RULE_EMBEDDED_REDIRECT",
    name: "Embedded Redirection / Open Redirect Pattern",
    triggered: hasEmbeddedRedirect,
    points: hasEmbeddedRedirect ? weights.embedded_redirect : 0,
    severity: "MEDIUM",
    explanation: hasEmbeddedRedirect
      ? "URL contains nested URLs or open-redirect structures, which attackers use to forward authenticated visitors to malicious landing pages."
      : "No embedded redirect or anomalous slash patterns found.",
    detail: redirectDetail
  });

  // -------------------------------------------------------------
  // Check 14: Heavy Percent / Hex Encoding
  // -------------------------------------------------------------
  const encodedMatches = raw.match(/%[0-9a-fA-F]{2}/g) || [];
  const hasHeavyEncoding = encodedMatches.length > thresholds.maxEncodedCharsCount;
  checks.push({
    id: "RULE_HEAVY_ENCODING",
    name: "Heavy Percent / Hex Obfuscation",
    triggered: hasHeavyEncoding,
    points: hasHeavyEncoding ? weights.heavy_encoding : 0,
    severity: "LOW",
    explanation: hasHeavyEncoding
      ? `URL contains ${encodedMatches.length} percent-encoded tokens (%xx). Heavy hex encoding is frequently used to conceal suspicious keywords or filenames.`
      : "Normal character encoding levels.",
    detail: `Found ${encodedMatches.length} percent-encoded sequences: [${encodedMatches.slice(0, 5).join(", ")}${encodedMatches.length > 5 ? "..." : ""}]`
  });

  // -------------------------------------------------------------
  // Check 15: High Host Digit Ratio
  // -------------------------------------------------------------
  const hostWithoutDots = host.replace(/[^a-zA-Z0-9]/g, "");
  const digitCount = (host.match(/[0-9]/g) || []).length;
  const digitRatio = hostWithoutDots.length > 0 ? digitCount / hostWithoutDots.length : 0;
  const isHighDigitRatio = !anatomy.isIpHost && digitRatio > thresholds.maxDigitRatio && digitCount >= 3;
  checks.push({
    id: "RULE_HIGH_DIGIT_RATIO",
    name: "High Host Digit Ratio (Numeric Obfuscation)",
    triggered: isHighDigitRatio,
    points: isHighDigitRatio ? weights.high_digit_ratio : 0,
    severity: "LOW",
    explanation: isHighDigitRatio
      ? `Hostname contains a high proportion of numerical digits (${(digitRatio * 100).toFixed(1)}%). Phishers often generate randomized domains with numbers.`
      : "Hostname character distribution contains standard alphabetic balance.",
    detail: `Host digits: ${digitCount} / ${hostWithoutDots.length} chars (${(digitRatio * 100).toFixed(1)}% | Threshold: > ${(thresholds.maxDigitRatio * 100)}%)`
  });

  return checks;
}

/**
 * Main analysis function that runs validation, anatomy extraction, and all 15 heuristic checks.
 * NEVER connects to the internet or fetches the target URL.
 * 
 * @param {string} inputUrl 
 * @returns {object} Complete analysis data object
 */
export function analyzeUrl(inputUrl) {
  const validation = validateUrlInput(inputUrl);
  if (!validation.valid) {
    return {
      success: false,
      error: validation.error
    };
  }

  const anatomy = parseUrlAnatomy(validation.sanitizedUrl);
  const checks = runSecurityChecks(anatomy, validation.schemeAssumed);

  // Extract suspicious portions for anatomy visualization highlights
  const suspiciousTokens = [];
  if (checks.find(c => c.id === "RULE_IP_HOST" && c.triggered)) {
    suspiciousTokens.push({ type: "host", text: anatomy.host, reason: "IP address as host" });
  }
  if (checks.find(c => c.id === "RULE_NO_HTTPS" && c.triggered)) {
    suspiciousTokens.push({ type: "protocol", text: anatomy.protocol, reason: "Insecure protocol" });
  }
  if (checks.find(c => c.id === "RULE_UNUSUAL_PORT" && c.triggered)) {
    suspiciousTokens.push({ type: "port", text: `:${anatomy.explicitPort}`, reason: "Non-standard port" });
  }
  if (checks.find(c => c.id === "RULE_BRAND_IMPERSONATION" && c.triggered)) {
    suspiciousTokens.push({ type: "brand", text: anatomy.subdomain || anatomy.host, reason: "Brand impersonation" });
  }
  if (checks.find(c => c.id === "RULE_SUSPICIOUS_KEYWORDS" && c.triggered)) {
    suspiciousTokens.push({ type: "keywords", text: anatomy.pathname, reason: "Credential keywords" });
  }
  if (checks.find(c => c.id === "RULE_AT_SYMBOL" && c.triggered)) {
    suspiciousTokens.push({ type: "authority", text: "@", reason: "@ credential authority spoofing" });
  }

  return {
    success: true,
    inputUrl: inputUrl.trim(),
    sanitizedUrl: validation.sanitizedUrl,
    schemeAssumed: validation.schemeAssumed,
    analyzedAt: new Date().toISOString(),
    anatomy: {
      ...anatomy,
      suspiciousTokens
    },
    checks
  };
}
