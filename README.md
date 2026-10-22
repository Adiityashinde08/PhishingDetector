# Phishing URL Detector (PhishGuard)

> **First-Year CSIT Semester Integrated Project (PBL) — Progress Review-II (50% Milestone)**  
> *An Explainable, Zero-Fetch Cybersecurity URL Heuristic Analysis and Awareness Tool.*

---

## 📌 1. Project Overview

**Phishing URL Detector (PhishGuard)** is a client-side, explainable cybersecurity web application developed for **First-Year CSIT Project-Based Learning (PBL) Progress Review-II**.

Unlike traditional URL scanners that send HTTP requests to target links, PhishGuard conducts **100% offline, deterministic heuristic string analysis directly inside the user's browser**. It evaluates link syntax, protocol status, authority tricks, IP hostnames, homoglyph punycode, and lexical markers **without fetching, pinging, or connecting to the destination**.

### Core Educational Principles:
- **Zero-Fetch Architecture**: Never exposes the client machine to malware downloads or alerts attackers.
- **Explainable Cybersecurity**: Replaces obscure predictions with transparent, point-by-point rule breakdowns.
- **Dynamic Safety Percentage**: Visually displays an intuitive circular gauge representing URL safety.
- **Zero Framework Dependency**: 100% vanilla Web Standards (HTML5, CSS3, ES modules).

---

## ✨ 2. Key Features Implemented (Review-II 50% Milestone)

| Feature | Description | Implementation Status |
|---|---|---|
| **Circular Safety Gauge** | Large, prominent visual circular gauge displaying dynamic **Safety Percentage** (e.g. *87% Safe*). | ✅ 100% Operational |
| **Offline Analysis Engine** | 15 heuristic security checks inspecting syntax per RFC 3986 without network connections. | ✅ 100% Operational |
| **Explainable Breakdown** | "Why did the detector give this result?" rank-orders triggered indicators by weight. | ✅ 100% Operational |
| **Interactive URL Anatomy** | Visually deconstructs protocol, host, subdomains, port, path, query, and flags suspicious tokens. | ✅ 100% Operational |
| **Side-by-Side Comparison** | Compares two URLs in parallel to demonstrate how syntax drives divergent risk tiers. | ✅ 100% Operational |
| **Detection Test Lab** | Live built-in unit test suite verifying 16 edge cases and reporting rule-engine pass rates. | ✅ 100% Operational |
| **Scan History & Insights** | Persistent browser `localStorage` (`pud_history_v1`) with search, risk filters, and CSV export. | ✅ 100% Operational |
| **Detection Insights** | Calculates top most frequently triggered indicators dynamically from actual history logs. | ✅ 100% Operational |
| **Security Audit Report** | Generates formatted plain-text reports with one-click **Copy to Clipboard** and **Download TXT**. | ✅ 100% Operational |
| **Spot the Phish Quiz** | 5 interactive scenario-based questions with instant feedback and pedagogical explanations. | ✅ 100% Operational |
| **PBL Review-II Report** | Comprehensive 15-section academic report with live dynamically evaluated partial results. | ✅ 100% Operational |
| **4 Cyber UI Themes** | Cyber Cyan (Dark default), Matrix Green, Neon Purple, and Light Clean with local persistence. | ✅ 100% Operational |

---

## 🛠 3. Technology Stack

- **Markup**: Pure HTML5 (Semantic, accessible, WCAG-conscious structure)
- **Styling**: Vanilla CSS3 (Custom properties, CSS Grid, Flexbox, hardware-accelerated transitions)
- **Logic**: Vanilla ECMAScript 2020+ ES Modules (No Node.js runtime, zero bundler dependencies)
- **Graphics & Icons**: Inline SVG vector graphics
- **Persistence**: Web Storage API (`localStorage`)
- **Compatibility**: Chrome 90+, Edge 90+, Firefox 88+, Safari 14+ (Desktop and Mobile)

---

## 🚀 4. How to Run Locally

Because the project uses modern **JavaScript ES Modules (`import`/`export`)**, it must be served through an HTTP server rather than opening `file:///` directly (to satisfy browser CORS module security policies).

### Option 1: Python HTTP Server (Recommended)
```bash
# Navigate to project folder
cd phishing-url-detector

# Start standard Python HTTP server on port 8000
python -m http.server 8000
```
Open your browser at: `http://localhost:8000`

### Option 2: VS Code Live Server Extension
1. Open the `phishing-url-detector/` folder in Visual Studio Code.
2. Right-click `index.html` and select **"Open with Live Server"**.

### Option 3: Node.js `npx serve` (If Node is installed)
```bash
npx serve .
```

---

## 📂 5. Project Directory Structure

```
phishing-url-detector/
├── index.html                  # Main application interface and tab panels
├── README.md                   # Complete project documentation and guide
├── CUSTOMIZE.md                # Student configuration and branding tutorial
├── assets/
│   ├── institute-logo.svg      # Official institute crest / placeholder
│   ├── logo.svg                # PhishGuard brand identity vector
│   └── favicon.svg             # Application tab icon
├── content/
│   └── about.js                # All 15 PBL academic sections, quiz questions, and literature
├── css/
│   ├── variables.css           # 4 theme palettes, typography, and geometry variables
│   ├── base.css                # Layout resets, navbar, typography, and footer
│   ├── components.css          # Gauge, cards, tables, inputs, accordions, and modals
│   └── responsive.css          # Responsive breakpoints for mobile, tablet, and desktop
├── js/
│   ├── main.js                 # Central controller orchestrating all modules
│   ├── site.config.js          # Institutional branding, team members, and thresholds
│   ├── config.js               # Rule definitions, point weights, keywords, and brands
│   ├── analyzer.js             # 100% offline lexical parser and 15 heuristic rules
│   ├── scorer.js               # Bounded risk scoring and safety percentage calculator
│   ├── results.js              # Gauge animation, anatomy cards, and breakdown renderer
│   ├── history.js              # localStorage manager (pud_history_v1) and CSV exporter
│   ├── stats.js                # Aggregate analytics and real-time detection insights
│   ├── samples.js              # Controlled safe demo URLs using reserved domains
│   ├── theme.js                # 4-theme switcher with persistence
│   ├── comparison.js           # Side-by-side URL feature difference matrix
│   ├── testLab.js              # 16-test automated heuristic validation runner
│   ├── report.js               # Plain-text security audit report generator
│   └── ui.js                   # Toast notifications, modal windows, and SVG helpers
├── tests/
│   ├── tests.html              # Standalone unit test suite runner page
│   └── analyzer.test.js        # Automated test execution and table renderer
└── docs/
    ├── PBL_MAPPING.md          # Rubric mapping, demonstration script, and viva Q&A
    └── ARCHITECTURE.md         # Full system architecture and heuristic math specifications
```

---

## 🔬 6. Detection Methodology & Mathematical Formulation

### 1. Risk Score Computation
The raw Risk Score is the bounded summation of triggered heuristic rule weights:

$$\text{Risk Score} = \min\left(100, \sum_{i=1}^{15} w_i \cdot \mathbb{I}(\text{Rule}_i)\right)$$

Where $w_i$ is the configured point weight for Rule $i$, and $\mathbb{I}(\text{Rule}_i) \in \{0, 1\}$ represents the boolean trigger condition.

### 2. Safety Percentage Derivation
Safety Percentage exhibits a direct, transparent inverse relationship with the calculated Risk Score:

$$\text{Safety Percentage} = \max\left(0, \min\left(100, 100 - \text{Risk Score}\right)\right)$$

### 3. Classification & Risk Tiers
- **LOW RISK**: $70\% - 100\%$ Safe $\implies$ Green *(Safe / Low-Risk)*
- **MEDIUM RISK**: $40\% - 69\%$ Safe $\implies$ Yellow *(Caution / Suspicious)*
- **HIGH RISK**: $0\% - 39\%$ Safe $\implies$ Red *(Danger / Phishing)*

---

## 🧪 7. Controlled Demo Samples & Verified Results

All demo URLs utilize **RFC 2606 reserved domains (`.example.test`)** or trusted academic portals to prevent real network hazards:

| Sample Category | Sample URL | Calculated Risk Score | Calculated Safety % | Risk Level | Triggered Indicators |
|---|---|:---:|:---:|:---:|---|
| **Safe Demo** | `https://www.wikipedia.org` | **0 / 100** | **100% Safe** | **LOW RISK** | None (All 15 Passed) |
| **Safe Demo** | `https://www.python.org/downloads/` | **0 / 100** | **100% Safe** | **LOW RISK** | None (All 15 Passed) |
| **Suspicious Demo** | `http://example-bank-login.example.test/` | **29 / 100** | **71% Safe** | **LOW / MED** | No HTTPS (+15), Keywords (+14) |
| **Phishing Demo** | `http://192.168.10.5:8080/secure/login/verify-account.php` | **69 / 100** | **31% Safe** | **HIGH RISK** | IP Host (+25), Port 8080 (+15), No HTTPS (+15), Keywords (+14) |
| **Phishing Demo** | `http://paypal.com.account-verify.example.test/login@update` | **71 / 100** | **29% Safe** | **HIGH RISK** | Brand Spoof (+22), @ Symbol (+20), No HTTPS (+15), Keywords (+14) |

---

## 🔒 8. Limitations & Scope Boundary (PBL Review-II)

1. **String-Only Heuristics**: The detector evaluates lexical and syntactic patterns of the URL string. It cannot detect a legitimate hacked website serving zero-day malware without syntactic URL anomalies.
2. **Offline Rule-Based Prototype**: Does not execute machine learning models or connect to live Google Safe Browsing APIs.
3. **No Safety Guarantee**: A high safety percentage reflects that no known suspicious heuristics were triggered; it does not guarantee absolute safety.

---

## 🔮 9. Future Work (Post-Review II Roadmap)

- [ ] **Machine Learning Classifier**: Training Random Forest / XGBoost models on the UCI Phishing dataset.
- [ ] **Manifest V3 Browser Extension**: Passive real-time hyperlink inspection on hover.
- [ ] **Backend WHOIS & DNS Integration**: Asynchronous domain age and registrar verification.
- [ ] **Live Threat Intelligence Feeds**: Integration with PhishTank and APWG feeds.

---

## 📚 10. References & Literature Sources

1. **RFC 3986**: Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform Resource Identifier (URI): Generic Syntax.* IETF.
2. **APWG Reports**: Anti-Phishing Working Group. (2024). *Phishing Activity Trends Report.*
3. **UCI Dataset**: Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). *Phishing Websites Data Set.* UCI Machine Learning Repository.
4. **OWASP**: *OWASP Top 10 Web Application Security Risks.*
5. **National Cyber Crime Reporting Portal (Govt. of India)**: [cybercrime.gov.in](https://cybercrime.gov.in) (Helpline: 1930).
