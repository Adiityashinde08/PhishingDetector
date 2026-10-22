/**
 * Phishing URL Detector - PBL Progress Review-II Academic Content
 * Written for First-Year CSIT undergraduate level in clean, professional English.
 * Supports all 15 required review sections, Quiz questions, and Learn guide.
 */

export const pblContent = {
  metadata: {
    projectTitle: "Explainable Phishing URL Detector via Rule-Based String Heuristics",
    reviewStage: "PBL Progress Review-II (50% Milestone)",
    academicLevel: "First-Year B.Tech CSIT (Semester II)",
    evaluationDate: "Academic Year 2025 - 2026"
  },

  // Section 1: Introduction
  introduction: {
    title: "1. Introduction",
    summary: "Phishing is one of the most pervasive cyber threats in modern digital communication, where attackers deceive victims into divulging sensitive credentials, financial data, or personal information using fraudulent web links.",
    paragraphs: [
      "In modern network security, traditional web crawlers or blacklisting mechanisms often visit or ping suspicious links to assess their threat level. However, visiting an unknown URL exposes the client machine to drive-by malware downloads, browser exploits, and zero-day vulnerabilities, while also alerting the attacker via web server access logs.",
      "This Project-Based Learning (PBL) project presents a client-side, zero-fetch Phishing URL Detector designed specifically for Semester Integrated Project Review-II. The system conducts 100% offline, deterministic heuristic string analysis directly inside the user's browser, inspecting syntax, protocol, domain structure, authority tricks, and lexical indicators without sending a single network packet to the destination server.",
      "The project focuses on explainable cybersecurity: rather than outputting an opaque prediction, it visually decomposes the URL anatomy and details exactly which security heuristics triggered the risk score."
    ]
  },

  // Section 2: Motivation & Need
  motivation: {
    title: "2. Motivation & Need",
    points: [
      {
        heading: "Escalating Phishing Attacks",
        text: "According to global cyber threat reports, millions of new deceptive URLs appear every month, targeting banking, social media, and digital payment platforms."
      },
      {
        heading: "Risk of Active URL Verification",
        text: "Standard safety tools often fetch page content or render HTML. For unvetted links, active network requests expose users to payload execution and allow adversaries to track target engagement."
      },
      {
        heading: "Need for Explainability in Defense Tools",
        text: "Many modern cybersecurity tools act as 'black boxes'. End-users and CSIT students need to understand WHY a specific link is dangerous to build long-term security awareness."
      },
      {
        heading: "Privacy-Preserving Local Inspection",
        text: "Corporate policies and individual privacy frequently prohibit sending confidential internal links or intranet addresses to third-party cloud threat scanners."
      }
    ]
  },

  // Section 3: Objectives
  objectives: {
    title: "3. Objectives",
    items: [
      "Develop an offline, in-browser URL lexical analysis engine using vanilla JavaScript ES modules without external network dependencies.",
      "Implement a transparent, deterministic scoring engine with 15+ distinct rule-based heuristic checks covering protocol, host type, domain depth, and lexical patterns.",
      "Calculate and visually display an intuitive Safety Percentage alongside Risk Score and discrete Risk Levels (LOW, MEDIUM, HIGH).",
      "Build an interactive 'URL Anatomy' decomposition module that highlights suspicious components for educational and presentation purposes.",
      "Create a side-by-side URL Comparison tool to demonstrate why visually similar URLs exhibit drastically different security postures.",
      "Provide an automated Detection Test Lab verifying edge cases and rule-engine pass rates.",
      "Deliver an educational 'Spot the Phish' quiz and awareness documentation linked to verified cyber safety resources like cybercrime.gov.in."
    ]
  },

  // Section 4: Literature Survey
  literatureSurvey: {
    title: "4. Literature Survey",
    note: "All citations represent real, verified academic publications, RFC standards, and security organizations.",
    papers: [
      {
        citation: "RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax (Berners-Lee, Fielding, & Masinter, 2005)",
        finding: "Defines the authoritative grammar of URIs, including scheme, authority (userinfo@host:port), path, query, and fragment. Phishing attacks exploit permissive authority syntax, such as abusing '@' to disguise the genuine destination host."
      },
      {
        citation: "APWG (Anti-Phishing Working Group) Phishing Activity Trends Reports (2023 - 2024)",
        finding: "Reports that the financial, social media, and SaaS sectors account for over 65% of all phishing campaigns. Highlights that free TLDs, shortened URLs, and IP address hostnames are consistently over-represented in phishing infrastructure."
      },
      {
        citation: "Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). 'An Assessment of Features Related to Phishing Websites using an Automated Web Crawler.' University of Huddersfield & UCI Machine Learning Repository.",
        finding: "Identified 30 structural and lexical features of phishing URLs, proving that offline lexical indicators (URL length, prefix/suffix hyphens, multiple subdomains, HTTPS presence) carry strong statistical correlation with maliciousness."
      },
      {
        citation: "OWASP (Open Web Application Security Project) - Top 10 Web Application Security Risks",
        finding: "Emphasizes the severity of Unvalidated Redirects and Forwards and Social Engineering credential attacks, demonstrating the necessity of client-side inspection before clicking untrusted hyperlinks."
      }
    ]
  },

  // Section 5: Problem Statement
  problemStatement: {
    title: "5. Problem Statement",
    statement: "Everyday Internet users and corporate personnel frequently receive unsolicited hyperlinks via email, SMS, and messaging apps. Existing web-based security verification solutions either require sending the URL to remote third-party cloud servers (compromising privacy) or actively connect to the destination server (risking client compromise). Furthermore, current scanners provide binary or obscure labels without explaining the underlying syntactic anomalies that signal deception. There is a lack of a transparent, client-side, explainable heuristic tool that inspects URL strings offline and educates users on link anatomy."
  },

  // Section 6: Solution Proposed
  solutionProposed: {
    title: "6. Proposed Solution",
    overview: "We propose 'PhishGuard: Explainable Phishing URL Detector', a lightweight, 100% client-side web application built with HTML5, CSS3, and vanilla JavaScript ES modules. The system never opens a network socket to the target link. Instead, it parses the URL string conforming to RFC 3986, extracts structural lexical features, evaluates 15 independent heuristic security checks, computes a transparent Risk Score and Safety Percentage, and presents an interactive visual breakdown of URL anatomy with contextual defensive recommendations."
  },

  // Section 7: Approach & Methodology
  methodology: {
    title: "7. Approach & Methodology",
    steps: [
      {
        step: "1. Input Normalization & Boundary Validation",
        detail: "Input strings are trimmed and validated against RFC 7230 length boundaries (<= 2048 characters). If a protocol scheme is absent, 'http://' is tentatively prepended with explicit user notification."
      },
      {
        step: "2. Grammatical Parsing & Anatomical Decomposition",
        detail: "The URL is segmented into protocol, authority, host, registered root domain, subdomain count, port, path, query, and fragment using standardized parsing algorithms."
      },
      {
        step: "3. Lexical Feature Extraction",
        detail: "Computes quantitative metrics: total length, subdomain depth, hyphen frequency, digit-to-letter ratios, percent-encoding frequencies, and regular expression pattern matches."
      },
      {
        step: "4. Heuristic Rule Evaluation",
        detail: "Executes 15 discrete security rules covering IP hosts, brand impersonation, lack of HTTPS, credential keywords, port anomalies, IDN punycode, and open redirects."
      },
      {
        step: "5. Multi-Metric Scoring & Classification",
        detail: "Computes Risk Score (sum of points capped at 100), derives Safety Percentage (100 - Risk Score), assigns Risk Level (LOW, MEDIUM, HIGH), and categorizes into SAFE, SUSPICIOUS, or PHISHING."
      },
      {
        step: "6. Explainable Presentation & Audit Generation",
        detail: "Renders an animated circular Safety Gauge, rank-ordered trigger justifications, interactive anatomy badges, and exportable plain-text security audit reports."
      }
    ]
  },

  // Section 8: System Architecture
  systemArchitecture: {
    title: "8. System Architecture",
    description: "The system follows a unidirectional, pipeline-based client-side architecture where data flows sequentially from user input to final visualization and local persistence.",
    flowSteps: [
      { node: "User", role: "Provides target URL via Web UI or selects safe demo preset" },
      { node: "Input Validation Module", role: "Trims whitespace, enforces <= 2048 char RFC limit, flags missing scheme" },
      { node: "URL Parsing & Anatomy Module", role: "Extracts protocol, host, domain, subdomains, port, path, query, hash" },
      { node: "Feature Extraction Module", role: "Calculates lengths, counts, ratios, keywords, and encoding patterns" },
      { node: "15+ Heuristic Rules Engine", role: "Evaluates individual checks (IP host, brand spoofing, no HTTPS, etc.)" },
      { node: "Scoring & Safety Engine", role: "Computes Risk Score (0-100), Safety % (100-Risk), and Risk Level" },
      { node: "Risk Classification Module", role: "Classifies as SAFE (0-29), SUSPICIOUS (30-59), or PHISHING (60-100)" },
      { node: "Explainability & Visual Presentation", role: "Renders circular gauge, anatomy breakdown, triggers, and advice" },
      { node: "LocalStorage & Audit Reports", role: "Persists scan history under pud_history_v1 and generates audit reports" }
    ]
  },

  // Section 9: System Modules (15 Modules with Status)
  systemModules: [
    {
      id: 1,
      name: "URL Input & Validation Module",
      purpose: "Validates, cleans, and sanitizes input URL strings.",
      inputs: "Raw string from input box",
      processing: "Whitespace trimming, length check (<= 2048), scheme inference.",
      output: "Sanitized URL object or validation error",
      status: "Implemented"
    },
    {
      id: 2,
      name: "URL Parsing Module",
      purpose: "Deconstructs URL string into standardized RFC 3986 tokens.",
      inputs: "Sanitized URL string",
      processing: "Native URL parsing with RFC 3986 grammar decomposition.",
      output: "Anatomy object (protocol, host, path, port, query, hash)",
      status: "Implemented"
    },
    {
      id: 3,
      name: "Feature Extraction Module",
      purpose: "Computes lexical, structural, and numerical properties of URL tokens.",
      inputs: "Parsed URL components",
      processing: "Character counts, dot/hyphen frequency, digit ratio, regex matching.",
      output: "Quantitative feature dictionary",
      status: "Implemented"
    },
    {
      id: 4,
      name: "Rule-Based Detection Module",
      purpose: "Evaluates 15 independent heuristic checks against extracted features.",
      inputs: "Feature dictionary & Anatomy object",
      processing: "Iterates through enabled heuristic rules and computes boolean triggers.",
      output: "Array of 15 check objects with id, points, explanation, and detail",
      status: "Implemented"
    },
    {
      id: 5,
      name: "Risk Scoring Module",
      purpose: "Calculates unified risk score from triggered security checks.",
      inputs: "Array of evaluated checks",
      processing: "Aggregates rule weights, clamps total score to [0, 100].",
      output: "Integer Risk Score (0 to 100)",
      status: "Implemented"
    },
    {
      id: 6,
      name: "Safety Percentage Module",
      purpose: "Derives user-friendly safety metric from risk score.",
      inputs: "Risk Score (0 - 100)",
      processing: "Applies formula: Safety % = max(0, min(100, 100 - Risk Score)).",
      output: "Clamped Safety Percentage (0% to 100%)",
      status: "Implemented"
    },
    {
      id: 7,
      name: "Risk Classification Module",
      purpose: "Assigns discrete categorical labels and security risk tiers.",
      inputs: "Risk Score & Safety Percentage",
      processing: "Compares against site.config.js thresholds.",
      output: "Risk Level (LOW / MEDIUM / HIGH) & Classification (SAFE / SUSPICIOUS / PHISHING)",
      status: "Implemented"
    },
    {
      id: 8,
      name: "Explainable Results Module",
      purpose: "Presents transparent justification for the calculated scores.",
      inputs: "Triggered checks & rule weights",
      processing: "Sorts triggers by point weight descending; separates triggered vs passed.",
      output: "Structured explainability breakdown and all-checks view",
      status: "Implemented"
    },
    {
      id: 9,
      name: "URL Anatomy Module",
      purpose: "Visually decomposes and annotates URL segments for educational inspection.",
      inputs: "Parsed anatomy & triggered flags",
      processing: "Tags suspicious tokens (e.g. IP host, @ symbol, login path).",
      output: "Interactive interactive anatomy component with highlighting",
      status: "Implemented"
    },
    {
      id: 10,
      name: "History Module",
      purpose: "Locally stores and manages prior scans without external database.",
      inputs: "Scan results object",
      processing: "Manages JSON array in browser localStorage under key 'pud_history_v1'.",
      output: "Persistent scan history list, search/filter, and delete actions",
      status: "Implemented"
    },
    {
      id: 11,
      name: "Statistics & Insights Module",
      purpose: "Computes aggregate scan metrics and ranks most frequent risk indicators.",
      inputs: "Current scan history from localStorage",
      processing: "Calculates averages, category counts, and indicator frequency ranking.",
      output: "Live dashboard metrics and 'Detection Insights' ranking",
      status: "Implemented"
    },
    {
      id: 12,
      name: "Comparison Module",
      purpose: "Enables side-by-side heuristic comparison of two distinct URLs.",
      inputs: "URL A and URL B",
      processing: "Parallel execution of analyzer and scorer, building difference matrix.",
      output: "Side-by-side comparative table with color-coded risk flags",
      status: "Implemented"
    },
    {
      id: 13,
      name: "Test Lab Module",
      purpose: "Automated verification test runner executing edge-case unit tests.",
      inputs: "Suite of 16 controlled test cases with assertions",
      processing: "Synchronous test execution and performance measurement.",
      output: "Pass/Fail report, execution time, and rule-engine pass rate",
      status: "Implemented"
    },
    {
      id: 14,
      name: "Security Report Module",
      purpose: "Generates formatted text audit reports with copy and download options.",
      inputs: "Full scan analysis and scoring object",
      processing: "String formatting, clipboard API invocation, text file Blob creation.",
      output: "Plain-text audit report, 'Copy to Clipboard', and 'Download TXT'",
      status: "Implemented"
    },
    {
      id: 15,
      name: "Learn & Awareness Module",
      purpose: "Educational guide on phishing mechanisms, URL anatomy, and quiz.",
      inputs: "User quiz selections & educational articles",
      processing: "Interactive quiz grading, answer explanations, safety references.",
      output: "5-question quiz score, safety tips, and cybercrime.gov.in guidance",
      status: "Implemented"
    }
  ],

  // Section 10: Requirements Analysis and SRS
  srs: {
    title: "10. Requirements Analysis and SRS",
    functional: [
      "FR-1: The system shall accept URL strings up to 2048 characters via a responsive input field.",
      "FR-2: The system shall parse and validate URL syntax strictly offline without making HTTP requests.",
      "FR-3: The system shall evaluate 15 independent heuristic security checks and compute individual point contributions.",
      "FR-4: The system shall calculate an overall Risk Score (0-100) and derive a Safety Percentage (100 - Risk Score).",
      "FR-5: The system shall assign discrete Risk Levels (LOW, MEDIUM, HIGH) and Classifications (SAFE, SUSPICIOUS, PHISHING).",
      "FR-6: The system shall display an explainable breakdown of triggered rules sorted by severity.",
      "FR-7: The system shall decompose and display URL anatomy (protocol, host, subdomain, port, path, query, hash).",
      "FR-8: The system shall provide side-by-side comparison for two arbitrary URLs.",
      "FR-9: The system shall maintain client-side scan history in localStorage with CSV export capability.",
      "FR-10: The system shall run an integrated automated test suite and report rule-engine pass rates."
    ],
    nonFunctional: [
      "NFR-1 (Privacy & Security): Zero outbound network connections to scanned targets. Zero server-side tracking.",
      "NFR-2 (Performance): Heuristic analysis and UI rendering must complete within 20 milliseconds per URL.",
      "NFR-3 (Usability & Responsiveness): Fluid responsive layout across mobile (360px), tablet (768px), and desktop (1280px+).",
      "NFR-4 (Explainability): Every flagged risk point must provide a clear human-readable explanation and technical detail.",
      "NFR-5 (Portability): 100% vanilla web standard implementation requiring no build step, node modules, or external CDN."
    ],
    specifications: {
      hardwareMin: "Any modern computing device with at least 2 GB RAM and dual-core processor (x86/x64/ARM).",
      softwareMin: "Any modern web browser supporting ECMAScript 2020+ (Chrome 90+, Firefox 88+, Edge 90+, Safari 14+).",
      devEnvironment: "Visual Studio Code with Live Server extension OR Python 3 HTTP server (`python -m http.server 8000`)."
    }
  },

  // Section 11: Code Implementation (50% Milestone Summary & Snippets)
  codeImplementation: {
    title: "11. Code Implementation (50% Milestone)",
    summary: "As of Progress Review-II, the foundational 50% milestone is fully achieved: the complete offline analysis engine, 15 security heuristics, scoring logic, safety percentage derivation, scan history persistence, comparison module, test suite, and responsive UI are fully implemented and functioning.",
    snippets: [
      {
        name: "Snippet 1: Offline Input Normalization & Scheme Assumption",
        code: `export function validateUrlInput(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return { valid: false, error: "Please enter a URL." };
  const trimmed = rawInput.trim();
  if (trimmed.length > 2048) return { valid: false, error: "URL exceeds 2048 characters." };
  
  let sanitized = trimmed;
  let schemeAssumed = false;
  if (!/^[a-zA-Z][a-zA-Z0-9+\\-.]*:\\/\\//i.test(sanitized)) {
    sanitized = "http://" + sanitized;
    schemeAssumed = true;
  }
  return { valid: true, sanitizedUrl: sanitized, schemeAssumed };
}`
      },
      {
        name: "Snippet 2: Transparent Safety Percentage & Risk Score Derivation",
        code: `// Risk Score is the bounded sum of triggered rule weights
const rawRisk = triggeredChecks.reduce((sum, c) => sum + c.points, 0);
const riskScore = Math.max(0, Math.min(100, Math.round(rawRisk)));

// Safety Percentage has a direct, transparent inverse relationship with Risk Score
const safetyPercentage = Math.max(0, Math.min(100, 100 - riskScore));

// Categorize Risk Level based on configurable thresholds
const riskLevel = safetyPercentage >= 70 ? "LOW" : safetyPercentage >= 40 ? "MEDIUM" : "HIGH";`
      },
      {
        name: "Snippet 3: IP Address Host Detection Rule",
        code: `const isIpv4 = /^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/.test(host);
const isIpv6 = host.includes(":") && /^[\\[\\]a-fA-F0-9:]+$/.test(host);
const isIpHost = isIpv4 || isIpv6;

checks.push({
  id: "RULE_IP_HOST",
  name: "IP Address as Hostname",
  triggered: isIpHost,
  points: isIpHost ? 25 : 0,
  severity: "HIGH",
  explanation: "Using an IP literal instead of a domain name evades reputation filters."
});`
      },
      {
        name: "Snippet 4: Brand Impersonation in Subdomain / Path",
        code: `let brandSpoof = false;
for (const brand of targetBrands) {
  const inSubdomain = anatomy.subdomain.includes(brand.name);
  const inPath = anatomy.pathname.includes(brand.name);
  const isOfficial = brand.officialDomains.some(d => host === d || host.endsWith("." + d));
  
  if ((inSubdomain || inPath) && !isOfficial) {
    brandSpoof = true;
    break;
  }
}`
      }
    ]
  },

  // Section 12: Demonstration of Modules
  moduleDemonstration: {
    title: "12. Demonstration of System Modules",
    description: "The application is organized into interactive functional modules accessible via the top navigation bar:",
    demos: [
      { tab: "Scanner", action: "Enter any URL or click safe demo presets to view the Safety Gauge, Risk breakdown, and URL Anatomy." },
      { tab: "Compare", action: "Compare legitimate URLs (e.g. Wikipedia) against phishing-style mockups side-by-side." },
      { tab: "Detection Test Lab", action: "Run the full automated test suite to verify all 16 unit assertions and observe execution times." },
      { tab: "History & Statistics", action: "Inspect stored scans, review 'Detection Insights' computed from actual history, and export CSV." },
      { tab: "Learn & Quiz", action: "Study URL structure safety principles and take the 5-question 'Spot the Phish' interactive challenge." },
      { tab: "About Project", action: "Review this complete 15-section PBL Progress Review-II report and live dynamic partial results." }
    ]
  },

  // Section 14: Conclusion & Future Work
  conclusion: {
    title: "14. Conclusion & Future Work",
    conclusionText: "At Progress Review-II, the Phishing URL Detector successfully demonstrates the feasibility, speed, and privacy advantages of client-side, zero-fetch URL inspection. By evaluating 15 transparent heuristic checks on raw URL strings, the system provides users with immediate, explainable risk assessments without exposing them to remote server interaction.",
    futureWorkNotice: "IMPORTANT: The following features are planned for future development (Post-Review II) and are NOT claimed as implemented in this prototype:",
    futureWorkItems: [
      { name: "Machine Learning Classifier", detail: "Train and evaluate lightweight Random Forest or Logistic Regression models using Scikit-Learn / TensorFlow.js on balanced public phishing datasets." },
      { name: "Browser Extension Integration", detail: "Package the heuristics engine into a Manifest V3 browser extension for real-time passive link hover scanning." },
      { name: "WHOIS & Domain Age Verification", detail: "Incorporate optional backend API proxy for domain registration age and registrar reputation lookups." },
      { name: "DNS Reputation & Live Threat Feeds", detail: "Integrate Google Safe Browsing / PhishTank threat feed lookups where online querying is permissible." }
    ]
  },

  // Section 15: Verified References
  references: {
    title: "15. References & Literature Sources",
    citationNote: "Verify and format references according to your institution's required citation style (IEEE / Harvard / APA) before final submission.",
    list: [
      "Berners-Lee, T., Fielding, R., & Masinter, L. (2005). 'Uniform Resource Identifier (URI): Generic Syntax.' RFC 3986, Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc3986",
      "Anti-Phishing Working Group (APWG). (2024). 'Phishing Activity Trends Report - Q4 2023.' APWG Technical Reports. https://apwg.org/trendsreports/",
      "Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). 'Phishing Websites Data Set.' UCI Machine Learning Repository. https://doi.org/10.24432/C51W2X",
      "Open Web Application Security Project (OWASP). (2021). 'OWASP Top 10 Web Application Security Risks.' OWASP Foundation. https://owasp.org/Top10/",
      "National Cyber Crime Reporting Portal, Ministry of Home Affairs, Government of India. https://cybercrime.gov.in"
    ]
  },

  // Educational Quiz (Spot the Phish)
  quiz: [
    {
      id: "q1",
      question: "Which of the following URL structures indicates that the user is being routed to an attacker's server?",
      scenario: "URL: http://paypal.com.account-verify.example.test/login",
      options: [
        "The URL is completely safe because 'paypal.com' is written at the beginning.",
        "The URL is suspicious because 'paypal.com' is merely a subdomain prefix; the actual destination domain is 'example.test'.",
        "The URL is safe because it uses standard HTTP port 80.",
        "The URL is safe because it contains the word 'login'."
      ],
      correctIndex: 1,
      explanation: "In domain hierarchy, the true host is read right-to-left from the TLD. Here, 'example.test' is the actual registered domain. Attackers frequently place trusted brand names into subdomains to trick casual observers."
    },
    {
      id: "q2",
      question: "Why does using a raw IP address (e.g., http://192.168.10.5:8080/login) represent an elevated phishing risk?",
      scenario: "URL: http://192.168.10.5:8080/secure/login/verify-account.php",
      options: [
        "IP addresses are illegal on the Internet.",
        "Legitimate institutions register branded domain names; raw IP addresses bypass domain reputation systems and lack public identity transparency.",
        "IP addresses can only transmit plain text without numbers.",
        "Browsers refuse to open any numeric IP address."
      ],
      correctIndex: 1,
      explanation: "Legitimate commercial institutions and banks always use registered domain names. Attackers often deploy temporary phishing hosts using raw IP addresses to evade automated domain reputation filters and avoid domain registration fees."
    },
    {
      id: "q3",
      question: "What is the security significance of the '@' symbol in a URL authority string?",
      scenario: "URL: https://www.google.com@attacker-site.test/login",
      options: [
        "It sends an encrypted email directly to the website owner.",
        "According to RFC 3986, characters before '@' represent user credentials (userinfo); the browser routes exclusively to the domain AFTER the '@'.",
        "It guarantees that Google has certified the webpage.",
        "It indicates that the website requires an administrative login."
      ],
      correctIndex: 1,
      explanation: "In URI syntax (RFC 3986), 'userinfo@host' uses '@' to separate credentials from the host. Browsers ignore whatever appears before '@' when establishing the network connection, routing the user straight to 'attacker-site.test'."
    },
    {
      id: "q4",
      question: "Does having an HTTPS (green padlock) connection guarantee that a website is NOT a phishing site?",
      scenario: "Scenario: An attacker registers 'secure-banking-alert.xyz' with a free Let's Encrypt SSL/TLS certificate.",
      options: [
        "Yes, HTTPS guarantees that the website is authenticated and completely legitimate.",
        "No, HTTPS only ensures that transport-layer traffic is encrypted; malicious phishers can easily obtain free SSL certificates for deceptive domains.",
        "Yes, cybercriminals are unable to obtain digital certificates.",
        "Yes, phishing attacks are technically impossible over port 443."
      ],
      correctIndex: 1,
      explanation: "HTTPS encrypts communications between the browser and the web server, protecting against eavesdropping. However, it does NOT verify the intent of the website owner. Millions of phishing websites operate with valid HTTPS certificates today."
    },
    {
      id: "q5",
      question: "What is an IDN Homograph / Punycode attack in phishing URLs?",
      scenario: "URL: https://xn--pple-43d.test (mimics 'apple.test' using Cyrillic glyphs)",
      options: [
        "An attack where the hacker physically unplugs the network cable.",
        "Using visually identical non-Latin characters (like Cyrillic 'а' or Greek 'ο') to register visually spoofed domains that trick the human eye.",
        "An attack that converts URLs into audio sound waves.",
        "A technique that deletes the browser's bookmark list."
      ],
      correctIndex: 1,
      explanation: "Internationalized Domain Names (IDNs) allow foreign alphabets in hostnames, encoded as 'xn--' Punycode. Attackers use lookalike glyphs (homoglyphs) to create domain names that look identical to legitimate brands in standard fonts."
    }
  ]
};
