# Customization & Student Configuration Guide

## Phishing URL Detector (PhishGuard)
**First-Year CSIT Semester Integrated Project (PBL)**

This project is architected with modular configuration files so you can easily personalize it with your college details, group member names, custom rule weights, and branding.

---

## 1. Quick Customization Summary

| What You Want to Change | File to Edit | Key Variables / Locations |
|---|---|---|
| **College Name & Department** | `js/site.config.js` | `siteConfig.institution.name`, `department` |
| **Official College Logo** | `assets/institute-logo.svg` | Replace file with your college's SVG or PNG |
| **Team Member Names & Roll Nos** | `js/site.config.js` | `siteConfig.teamMembers` array |
| **Faculty Guide / Mentor Details** | `js/site.config.js` | `siteConfig.guide.name`, `designation` |
| **Project Title & Tagline** | `js/site.config.js` | `siteConfig.projectName`, `tagline` |
| **Safety / Risk Thresholds** | `js/site.config.js` | `siteConfig.thresholds.safety`, `risk` |
| **Rule Point Weights** | `js/config.js` | `detectorConfig.weights` |
| **Keywords List** | `js/config.js` | `detectorConfig.suspiciousKeywords` |
| **Target Brands for Spoofing** | `js/config.js` | `detectorConfig.targetBrands` |
| **Suspicious TLDs** | `js/config.js` | `detectorConfig.suspiciousTlds` |
| **Demo URLs** | `js/samples.js` | `sampleUrls`, `sampleComparisonPairs` |
| **PBL Documentation Content** | `content/about.js` | `pblContent.introduction`, `objectives`, etc. |
| **Quiz Questions** | `content/about.js` | `pblContent.quiz` |
| **Theme Colors & Palettes** | `css/variables.css` | `--color-accent`, `--color-bg-base`, etc. |

---

## 2. Replacing the Official Institute Logo

Your institute's official logo is mandatory for PBL submissions.
1. Obtain your university or engineering college's official logo in `.svg` format (or `.png`).
2. Rename your file to `institute-logo.svg` (or update the filename in `js/site.config.js`).
3. Replace the placeholder file at:
   ```
   phishing-url-detector/assets/institute-logo.svg
   ```
4. If using a `.png` file, update line 19 in `js/site.config.js`:
   ```javascript
   logoPath: "assets/college-logo.png",
   ```

---

## 3. Updating Team Members and Faculty Guide

Open `js/site.config.js` and edit the placeholders:

```javascript
// Student Project Team
teamMembers: [
  {
    name: "AARAV SHARMA",
    rollNo: "24CSIT012",
    role: "Lead Developer (URL Parser & Engine)"
  },
  {
    name: "PRIYA VERMA",
    rollNo: "24CSIT045",
    role: "Frontend Designer (Gauge UI & Anatomy)"
  },
  {
    name: "ROHAN GUPTA",
    rollNo: "24CSIT078",
    role: "Security Researcher (Rule Weights & Testing)"
  },
  {
    name: "ANANYA SINGH",
    rollNo: "24CSIT091",
    role: "Documentation & PBL Analysis Lead"
  }
],

// Faculty Mentor
guide: {
  name: "DR. SURESH KUMAR",
  designation: "Associate Professor",
  department: "Department of CSIT",
  cabinOrEmail: "suresh.kumar@institute.edu"
}
```

---

## 4. Tuning Rule Weights and Thresholds

Open `js/config.js` to change how many risk points each heuristic contributes:

```javascript
export const detectorConfig = {
  weights: {
    ip_host: 25,              // Raw IP address host
    brand_impersonation: 22,  // Brand spoofing
    at_symbol: 20,            // RFC 3986 '@' userinfo trick
    no_https: 15,             // Plain HTTP protocol
    suspicious_keywords: 14,  // Credential keywords
    unusual_port: 15,         // Non-standard port (e.g. :8080)
    suspicious_tld: 15,       // Free or high-abuse TLDs
    url_shortener: 12,        // Known URL shorteners
    punycode_host: 16,        // IDN Homograph / Punycode (xn--)
    excessive_length: 10,     // Total length > 75 chars
    excessive_subdomains: 12, // Subdomain depth >= 3
    excessive_hyphens: 10,    // Hyphens >= 2 in host
    embedded_redirect: 14,    // Open redirect patterns
    heavy_encoding: 10,       // Hex / percent encoding (%xx)
    high_digit_ratio: 10      // Digits > 25% of hostname
  },
  
  thresholds: {
    maxUrlLengthNormal: 75,   // Trigger excessive length if > 75 chars
    maxSubdomains: 3,         // Trigger if subdomains >= 3
    maxHostHyphens: 2         // Trigger if hyphens in host >= 2
  }
};
```

---

## 5. Adding Brand Targets and Keywords

In `js/config.js`, you can add regional banks, university portals, or payment apps:

### Adding New Phishing Keywords:
```javascript
suspiciousKeywords: [
  "login", "verify", "otp", "aadhaar", "pan-update",
  "kyc-pending", "reward-points", "cashback-claim"
]
```

### Adding New Brand Targets for Impersonation Checks:
```javascript
targetBrands: [
  { name: "paytm", officialDomains: ["paytm.com"] },
  { name: "phonepe", officialDomains: ["phonepe.com"] },
  { name: "gpay", officialDomains: ["pay.google.com"] }
]
```

---

## 6. How to Add a New Detection Rule (Step-by-Step)

Suppose you want to add **Rule 16: Excessive Path Depth** (flags URLs with more than 5 nested directories `/a/b/c/d/e/f`):

### Step 1: Add Weight in `js/config.js`
```javascript
weights: {
  // ... existing weights
  excessive_path_depth: 10
}
```

### Step 2: Add Logic in `js/analyzer.js` inside `runSecurityChecks()`
```javascript
// Rule 16: Excessive Path Depth
const pathSegments = anatomy.pathname.split("/").filter(Boolean);
const isExcessivePath = pathSegments.length > 5;

checks.push({
  id: "RULE_PATH_DEPTH",
  name: "Excessive Directory Path Depth",
  triggered: isExcessivePath,
  points: isExcessivePath ? weights.excessive_path_depth : 0,
  severity: "LOW",
  explanation: isExcessivePath 
    ? `Path contains ${pathSegments.length} nested directory levels. Attackers use deep directories to evade superficial scanners.`
    : "Directory hierarchy depth is within normal limits.",
  detail: `Path segments count: ${pathSegments.length} (Max normal threshold: 5)`
});
```

### Step 3: Add a Test in `js/testLab.js`
```javascript
{
  id: "TC-17",
  name: "Excessive Directory Path Depth Rule",
  input: "https://example.test/a/b/c/d/e/f/g",
  expectedDescription: "Triggers RULE_PATH_DEPTH when path has > 5 segments",
  assert: (res) => {
    const c = res.checks.find(check => check.id === "RULE_PATH_DEPTH");
    return res.success && c && c.triggered === true;
  }
}
```

Your new rule will now automatically contribute to Risk Score, Safety Percentage, URL anatomy, report generation, and the test suite!
