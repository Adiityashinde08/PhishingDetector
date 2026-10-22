/**
 * Phishing URL Detector - Site & Project Configuration
 * Easily customizable metadata for student PBL submissions and institutional branding.
 */

export const siteConfig = {
  // Project Information
  projectName: "Phishing URL Detector",
  projectShortName: "PhishGuard",
  projectTagline: "Understand the risk before you trust the link.",
  projectSubtitle: "First-Year CSIT Project-Based Learning (PBL) — Progress Review-II",
  version: "2.1.0-review2",
  reviewStage: "Progress Review-II (50% Milestone)",

  // Academic & Institutional Information
  institution: {
    name: "YOUR INSTITUTE / COLLEGE OF ENGINEERING",
    shortName: "YOUR COLLEGE",
    department: "Department of Computer Science & Information Technology",
    course: "B.Tech Computer Science & Information Technology",
    semester: "Semester II",
    academicYear: "2025 - 2026",
    logoPath: "assets/institute-logo.svg", // Replace with official institute SVG/PNG
    logoPlaceholderText: "ADD OFFICIAL INSTITUTE LOGO"
  },

  // Project Faculty Guide / Mentor
  guide: {
    name: "PROF. / DR. FACULTY MENTOR NAME",
    designation: "Assistant Professor / Associate Professor",
    department: "Department of CSIT",
    cabinOrEmail: "mentor@institute.edu"
  },

  // Student Project Team (Configurable placeholders — replace with your team details)
  teamMembers: [
    {
      name: "STUDENT 1 NAME",
      rollNo: "CSIT-2025-001",
      role: "Lead Developer (URL Parser & Detection Engine)"
    },
    {
      name: "STUDENT 2 NAME",
      rollNo: "CSIT-2025-002",
      role: "Frontend Designer (Gauge UI & Interactive Anatomy)"
    },
    {
      name: "STUDENT 3 NAME",
      rollNo: "CSIT-2025-003",
      role: "Security Researcher (Rule Weights & Test Suite)"
    },
    {
      name: "STUDENT 4 NAME",
      rollNo: "CSIT-2025-004",
      role: "Documentation & PBL Analysis Lead"
    }
  ],

  // Safety & Risk Thresholds (Configurable)
  // Default relationship: Safety Percentage = 100 - Risk Score
  thresholds: {
    safety: {
      lowRiskMin: 70,    // 70 - 100% Safe -> LOW RISK
      mediumRiskMin: 40, // 40 - 69% Safe  -> MEDIUM RISK
      highRiskMax: 39    // 0 - 39% Safe   -> HIGH RISK
    },
    risk: {
      safeMax: 29,         // 0 - 29 Risk  -> Classification: SAFE
      suspiciousMax: 59,   // 30 - 59 Risk -> Classification: SUSPICIOUS
      phishingMin: 60      // 60 - 100 Risk -> Classification: PHISHING
    }
  },

  // Risk Level Labels and Visual Attributes
  riskLevels: {
    LOW: {
      key: "LOW",
      label: "LOW RISK",
      badgeClass: "badge-low",
      color: "var(--color-safe)",
      summary: "No major suspicious URL patterns detected",
      recommendation: "Standard browsing hygiene recommended. Always verify the domain before submitting sensitive credentials."
    },
    MEDIUM: {
      key: "MEDIUM",
      label: "MEDIUM RISK",
      badgeClass: "badge-medium",
      color: "var(--color-warning)",
      summary: "Proceed carefully and verify the domain",
      recommendation: "Elevated risk indicators observed. Verify the SSL certificate and check if the domain matches the expected service."
    },
    HIGH: {
      key: "HIGH",
      label: "HIGH RISK",
      badgeClass: "badge-high",
      color: "var(--color-danger)",
      summary: "Do not enter passwords, OTPs or financial information",
      recommendation: "Multiple strong phishing indicators triggered. Do not interact with forms, download files, or enter passwords."
    }
  },

  // Privacy & Offline Guarantee Notices
  privacyNotice: {
    headline: "🛡 Local Analysis",
    subtext: "Your URL is analyzed in this browser. We do not visit or send the URL anywhere.",
    points: [
      "No URL fetching or HTTP pinging",
      "No DNS lookup or IP resolution",
      "No WHOIS lookup or domain ownership query",
      "No external API or cloud dependency",
      "No password, credential, or telemetry collection",
      "Zero connection to the entered website"
    ]
  },

  educationalDisclaimer: "This is an educational rule-based prototype. Results are based only on URL-string analysis and do not guarantee that a link is safe or malicious.",
  safetyScoreNote: "Safety percentage represents the result of our rule-based URL analysis. It is not a guarantee of website safety.",

  // Feature Toggles (enable/disable modules easily)
  features: {
    enableUrlComparison: true,
    enableDetectionTestLab: true,
    enableSecurityReportExport: true,
    enableHistoryLogging: true,
    enableQuiz: true,
    enableInteractiveAnatomy: true,
    enableDetectionInsights: true
  },

  // Storage Settings
  storage: {
    historyKey: "pud_history_v1",
    themeKey: "pud_theme_v1",
    maxHistoryItems: 50
  },

  // Cyber Safety Portal Reference (Indian National Cybercrime Reporting)
  cyberSafetyReference: {
    name: "National Cyber Crime Reporting Portal (Govt. of India)",
    url: "https://cybercrime.gov.in",
    helpline: "1930",
    disclaimer: "Note: This educational tool does not automatically report or verify URLs with cybercrime.gov.in. If you encounter active financial fraud, report it directly on the official portal or call 1930."
  }
};
