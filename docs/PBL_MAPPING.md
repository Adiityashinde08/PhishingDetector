# PBL Progress Review-II Academic Mapping & Viva Guide

## Course: First-Year B.Tech CSIT — Semester Integrated Project (PBL)
**Milestone:** Progress Review-II (50% Implementation Review)  
**Project Title:** Explainable Phishing URL Detector via Rule-Based String Heuristics  

---

## 1. PBL Review-II Evaluation Rubric Mapping

| Evaluation Criteria | Required Review-II Scope | Project Implementation Status | Location in Project |
|---|---|---|---|
| **Problem Formulation & Need** | Clear identification of cyber threat and limitation of existing tools | Identified privacy, active ping risk, and lack of explainability in existing black-box scanners | Tab: About Project (Sec 1, 2, 5) |
| **Literature Survey** | Genuine survey of RFCs, academic papers, and security standards | 4 verified citations: RFC 3986, APWG 2023-24, UCI Dataset (Mohammad et al.), OWASP | Tab: About Project (Sec 4, 15) |
| **Requirements & SRS** | Functional, non-functional, hardware, and software requirements | 10 Functional Requirements (FR-1 to FR-10), 5 Non-Functional (NFR-1 to 5), Hardware/Software specs | Tab: About Project (Sec 10) |
| **System Architecture & Design** | Clear modular breakdown and end-to-end data pipeline | Interactive visual SVG architecture diagram with 10 sequential pipeline stages | Tab: About Project (Sec 8, 9) |
| **Implementation Milestone (50%)** | Fully functional core analysis engine with live working code | **100% of Review-II scope implemented**: offline parser, 15 heuristics, scoring, history, comparison, test lab | Complete codebase (`js/*.js`) |
| **Live Demonstration Quality** | Live, non-faked execution of core features | Live scanning, dynamic circular gauge, interactive anatomy, side-by-side comparison, test suite | All tabs operational |
| **Explainability & Code Clarity** | Transparent algorithms suitable for first-year CSIT level | Clear points breakdown, zero obfuscated code, clean vanilla ES module design | Code snippets in Sec 11 |

---

## 2. Step-by-Step Demonstration Script for Review-II

Follow this exact 5-minute walkthrough during your faculty review:

### Step 1: Explain the Core Problem & Zero-Fetch Guarantee (1 minute)
1. Open the application in your browser.
2. Highlight the **"🛡 Local Analysis"** badge in the hero section and click it to open the drawer.
3. **Say:** *"Respected faculty, traditional scanners often connect to or ping suspicious links, which risks drive-by malware downloads and alerts the attacker. Our tool runs 100% offline in the browser without fetching the URL."*

### Step 2: Demonstrate Safe URL Analysis (1 minute)
1. Click the **"Wikipedia (Safe)"** demo chip and click **"Scan URL"**.
2. Point to the **Circular Safety Gauge**:
   - Shows **87% - 100% Safe**, **LOW RISK**, **SAFE**.
3. Point to **"Why Did the Detector Give This Result?"**:
   - Shows clean green status box: No major suspicious indicators triggered.
4. Point to the **URL Anatomy** section:
   - Explain how protocol, host, domain, and path are cleanly parsed per RFC 3986.

### Step 3: Demonstrate Phishing URL Analysis & Triggers (1.5 minutes)
1. Click the **"IP & Port 8080 (Demo)"** or **"Brand Spoof & @"** demo chip.
2. Click **"Scan URL"**:
   - Notice the gauge instantly transitions to **HIGH RISK** (Red) with high Risk Score.
3. Show the **Risk Breakdown**:
   - Point out individual point additions: `IP address as host (+25 pts)`, `No HTTPS (+15 pts)`, `Unusual port 8080 (+15 pts)`, `Suspicious keywords (+14 pts)`.
   - Explain that the score is the transparent bounded sum of triggered rules.
4. Click **"Expand All 15 Checks"**:
   - Show how all 15 rules were evaluated in parallel.
5. Click **"View Full Security Report"**:
   - Show the generated audit text and demonstrate **"Copy Report"** and **"Download TXT"**.

### Step 4: Demonstrate URL Comparison & Test Lab (1.5 minutes)
1. Navigate to **"⚖️ Compare URLs"**:
   - Click **"Wikipedia vs PayPal Brand Spoof"** and run comparison.
   - Explain why two URLs have different safety percentages based on syntactic differences.
2. Navigate to **"🧪 Detection Test Lab"**:
   - Click **"Run Test Suite"**.
   - Show the live execution of all 16 test cases, demonstrating 100% pass rate in $< 10$ milliseconds.
   - Point to the explicit note: *"This measures rule-engine pass rate, not real-world phishing accuracy."*

---

## 3. Likely Teacher / Evaluator Questions and Model Answers

### Q1: "Does your system use Machine Learning or AI?"
> **Model Answer:**  
> *"No, sir/ma'am. For Progress Review-II, our project implements a transparent, deterministic rule-based heuristic engine with 15 distinct security checks. We deliberately avoided claiming AI because a rule-based engine provides 100% explainability, requires zero remote server dependencies, and executes instantly offline. Training an actual ML classifier on the UCI Phishing Dataset is listed in Section 14 as Future Work for Final Review-III."*

### Q2: "How is the Safety Percentage calculated?"
> **Model Answer:**  
> *"The Safety Percentage has a direct and transparent inverse relationship with the Risk Score:  
> `Safety Percentage = clamp(100 - Risk Score, 0, 100)`  
> The Risk Score is the sum of weights of all triggered security checks (e.g. IP host is +25, brand impersonation is +22, no HTTPS is +15), capped at 100. If an attacker triggers multiple indicators totaling 70 points of risk, the Safety Percentage is dynamically calculated as 30% Safe, placing it into HIGH RISK."*

### Q3: "What if an attacker uses HTTPS with a valid SSL certificate?"
> **Model Answer:**  
> *"That is an excellent point, sir/ma'am. That is why our engine uses a multi-vector heuristic approach. Even if the attacker has an HTTPS certificate (meaning `RULE_NO_HTTPS` passes), our engine still inspects 14 other features such as brand impersonation in the subdomain, unusual ports, homoglyph punycode, credential keywords, and excessive hyphens. HTTPS only encrypts the wire; our heuristics inspect the deception in the URL string itself."*

### Q4: "Where is the scan history saved? Is there a backend database?"
> **Model Answer:**  
> *"For Review-II, all scan records are persisted locally inside the browser's `localStorage` under the key `pud_history_v1`. This preserves privacy because user browsing data never leaves their local device. We also implemented a working CSV Export function so users can download their local scan audit logs."*

### Q5: "What is an IDN Homograph attack, and how do you detect it?"
> **Model Answer:**  
> *"An IDN Homograph attack uses international characters from other alphabets, such as Cyrillic 'а' (U+0430) which looks visually identical to Latin 'a' (U+0061), to register fake domains like 'apple.com'. Browsers encode these internationalized domain names using Punycode, which begins with the prefix `xn--`. Our `RULE_PUNYCODE_HOST` inspects the host string for `xn--` or non-ASCII characters and flags homograph deception."*

---

## 4. What is Implemented vs Future Work Summary

### Currently Implemented (Review-II 50% Milestone):
- [x] Complete offline URL validation and sanitization (RFC 7230 <= 2048 chars).
- [x] RFC 3986 anatomical decomposition (scheme, host, domain, subdomains, port, path, query, hash).
- [x] 15 discrete heuristic security rules with customizable weights.
- [x] Transparent Risk Score (0-100) and inverted Safety Percentage calculation.
- [x] Animated SVG circular gauge with dynamic color states (Green, Amber, Red).
- [x] Explainable risk breakdown sorted by point weight.
- [x] Interactive URL anatomy visualizer with suspicious token badges.
- [x] Side-by-side URL comparison module.
- [x] Automated Detection Test Lab with 16 live unit assertions.
- [x] Scan history manager in `localStorage` with search, risk filters, and CSV export.
- [x] Real-time Detection Insights ranking top triggered indicators.
- [x] Exportable plain-text security audit report with copy and download options.
- [x] Interactive 5-question "Spot the Phish" quiz with explanations.
- [x] Comprehensive 15-section PBL Review-II academic report.
- [x] 4 cyber themes (Cyber Cyan, Matrix Green, Neon Purple, Light Clean).

### Future Work (Review-III / Final Semester Submission):
- [ ] Train a Scikit-Learn / TensorFlow.js Random Forest classifier on the UCI Phishing dataset.
- [ ] Manifest V3 browser extension for real-time passive link hover scanning.
- [ ] Backend API proxy for WHOIS domain registration age and DNS reputation.
- [ ] Integration with Google Safe Browsing and live threat intelligence feeds.
