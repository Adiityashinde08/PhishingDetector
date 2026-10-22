/**
 * Phishing URL Detector - Main Application Controller
 * Orchestrates URL scanning, comparison, test lab, history, quiz, and PBL report rendering.
 */

import { siteConfig } from "./site.config.js";
import { sampleUrls, sampleComparisonPairs } from "./samples.js";
import { analyzeUrl, validateUrlInput } from "./analyzer.js";
import { calculateRiskAndSafety } from "./scorer.js";
import { renderScanResults } from "./results.js";
import { initTheme, setTheme } from "./theme.js";
import { showToast, openModal, closeModal, escapeHtml } from "./ui.js";
import { saveScan, getHistory, deleteScan, clearHistory, filterHistory, exportHistoryAsCsv } from "./history.js";
import { calculateStatistics } from "./stats.js";
import { compareUrls, buildComparisonMatrix } from "./comparison.js";
import { runTestSuite } from "./testLab.js";
import { generateSecurityReportText, copyReportToClipboard, downloadReportAsFile } from "./report.js";
import { pblContent } from "../content/about.js";

// Global reference to the most recent scan result
let currentScanData = null;

// =============================================================================
// 1. INITIALIZATION & METADATA POPULATION
// =============================================================================
window.addEventListener("DOMContentLoaded", () => {
  // Initialize Theme
  initTheme();
  setupThemeSelector();

  // Populate Institutional & Academic Metadata
  populateAcademicMetadata();

  // Setup Event Listeners
  setupNavigationTabs();
  setupPrivacyDrawer();
  setupScannerForm();
  setupDemoChips();
  setupAllChecksToggle();
  setupSecurityReportActions();
  setupComparisonMode();
  setupTestLab();
  setupHistoryAndStats();
  setupQuiz();
  renderPblSections();

  // If scan history exists, refresh stats & history table; else load demo into scanner
  const history = getHistory();
  if (history.length > 0) {
    refreshHistoryAndStats();
  }

  // Pre-fill scanner with legitimate sample for initial exploration
  const urlInput = document.getElementById("url-input");
  if (urlInput && !urlInput.value) {
    urlInput.value = "https://www.wikipedia.org";
    executeScan("https://www.wikipedia.org");
  }
});

/**
 * Binds theme dropdown switcher.
 */
function setupThemeSelector() {
  const themeSelect = document.getElementById("theme-select");
  if (!themeSelect) return;

  themeSelect.addEventListener("change", (e) => {
    setTheme(e.target.value);
    showToast(`Theme switched to ${e.target.options[e.target.selectedIndex].text}`);
  });
}

/**
 * Fills student group placeholders, faculty guide, and institution names.
 */
function populateAcademicMetadata() {
  const inst = siteConfig.institution;
  const guide = siteConfig.guide;
  const team = siteConfig.teamMembers;

  const instHeader = document.getElementById("inst-logo-header");
  if (instHeader && inst.logoPath) {
    instHeader.src = inst.logoPath;
  }

  const pblTitle = document.getElementById("pbl-project-title");
  if (pblTitle) pblTitle.textContent = siteConfig.projectName;

  const pblInst = document.getElementById("pbl-institution-name");
  if (pblInst) pblInst.textContent = inst.name;

  const pblDept = document.getElementById("pbl-dept-info");
  if (pblDept) pblDept.textContent = `${inst.department} | ${inst.course} (${inst.semester})`;

  const pblGuideName = document.getElementById("pbl-guide-name");
  if (pblGuideName) pblGuideName.textContent = guide.name;

  const pblGuideDept = document.getElementById("pbl-guide-dept");
  if (pblGuideDept) pblGuideDept.textContent = `${guide.designation}, ${guide.department}`;

  const pblTeamList = document.getElementById("pbl-team-list");
  if (pblTeamList) {
    pblTeamList.innerHTML = team.map(m => `
      <div style="background: var(--color-bg-surface); padding: 0.4rem 0.6rem; border-radius: 4px; border: 1px solid var(--color-border);">
        <strong>${escapeHtml(m.name)}</strong> (${escapeHtml(m.rollNo)})<br>
        <small style="color: var(--color-text-dim);">${escapeHtml(m.role)}</small>
      </div>
    `).join("");
  }
}

// =============================================================================
// 2. TAB NAVIGATION
// =============================================================================
function setupNavigationTabs() {
  const navTabs = document.querySelectorAll("#main-nav-tabs .nav-link");
  const tabSections = document.querySelectorAll(".tab-content-section");

  function switchTab(targetTabId) {
    navTabs.forEach(btn => {
      const isTarget = btn.getAttribute("data-tab") === targetTabId;
      btn.classList.toggle("active", isTarget);
      btn.setAttribute("aria-selected", isTarget);
    });

    tabSections.forEach(sec => {
      sec.classList.toggle("active", sec.id === targetTabId);
    });

    window.scrollTo({ top: 0, behavior: "smooth" });

    // Trigger tab-specific refresh if needed
    if (targetTabId === "tab-history") {
      refreshHistoryAndStats();
    }
  }

  navTabs.forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");
      switchTab(target);
    });
  });

  // Footer tab navigation triggers
  document.querySelectorAll(".footer-nav-trigger").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.getAttribute("data-tab");
      switchTab(target);
    });
  });
}

// =============================================================================
// 3. PRIVACY DRAWER TOGGLE
// =============================================================================
function setupPrivacyDrawer() {
  const btn = document.getElementById("privacy-toggle-btn");
  const drawer = document.getElementById("privacy-drawer");
  if (!btn || !drawer) return;

  btn.addEventListener("click", () => {
    const isOpen = drawer.classList.toggle("open");
    btn.innerHTML = isOpen 
      ? `🛡 Local Analysis <span style="font-size: 0.7rem;">▲</span>` 
      : `🛡 Local Analysis <span style="font-size: 0.7rem;">▼</span>`;
  });
}

// =============================================================================
// 4. SCANNER FORM & EXECUTION
// =============================================================================
function setupScannerForm() {
  const form = document.getElementById("url-scan-form");
  const input = document.getElementById("url-input");
  const clearBtn = document.getElementById("btn-clear-input");

  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      executeScan(input.value);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      input.value = "";
      input.focus();
    });
  }
}

/**
 * Core scanning orchestrator.
 * Analyzes string 100% offline, computes scores, updates history, renders results.
 * @param {string} rawInput 
 */
export function executeScan(rawInput) {
  const inputEl = document.getElementById("url-input");
  if (inputEl) inputEl.value = rawInput;

  // Run validation
  const validation = validateUrlInput(rawInput);
  if (!validation.valid) {
    showToast(`⚠️ ${validation.error}`);
    return;
  }

  if (validation.schemeAssumed) {
    showToast(`ℹ️ Scheme omitted: Defaulted to 'http://' for inspection.`);
  }

  // Execute Offline Heuristic Engine
  const analysis = analyzeUrl(validation.sanitizedUrl);
  if (!analysis.success) {
    showToast(`❌ ${analysis.error}`);
    return;
  }

  // Calculate Scores, Safety %, Confidence, and Recommendations
  const scoring = calculateRiskAndSafety(analysis.checks, analysis.anatomy);

  currentScanData = {
    ...analysis,
    inputUrl: rawInput.trim(),
    scoring
  };

  // Render Visual Results
  renderScanResults(currentScanData);

  // Persist into LocalStorage History
  saveScan(currentScanData);
  refreshHistoryAndStats();
}

/**
 * Binds demo sample chips.
 */
function setupDemoChips() {
  const sampleMap = {
    wikipedia: "https://www.wikipedia.org",
    python: "https://www.python.org/downloads/",
    bank: "http://example-bank-login.example.test/",
    update: "http://secure-update.example.test/account/verify",
    ip_port: "http://192.168.10.5:8080/secure/login/verify-account.php",
    brand_at: "http://paypal.com.account-verify.example.test/login@update"
  };

  document.querySelectorAll(".demo-chip[data-sample]").forEach(chip => {
    chip.addEventListener("click", () => {
      const key = chip.getAttribute("data-sample");
      const url = sampleMap[key];
      if (url) {
        executeScan(url);
        showToast(`Loaded demo: ${chip.textContent.trim()}`);
      }
    });
  });
}

function setupAllChecksToggle() {
  const toggleBtn = document.getElementById("toggle-all-checks-btn");
  const container = document.getElementById("all-checks-container");
  const label = document.getElementById("all-checks-toggle-label");

  if (!toggleBtn || !container) return;

  toggleBtn.addEventListener("click", () => {
    const isHidden = container.style.display === "none";
    container.style.display = isHidden ? "block" : "none";
    if (label) {
      label.textContent = isHidden ? "Collapse Checks Table" : "Expand All 15 Checks";
    }
    toggleBtn.innerHTML = isHidden 
      ? `<span>${label.textContent}</span> ▲` 
      : `<span>${label.textContent}</span> ▼`;
  });
}

// =============================================================================
// 5. SECURITY REPORT MODAL & EXPORT
// =============================================================================
function setupSecurityReportActions() {
  const viewReportBtn = document.getElementById("btn-generate-report");
  const copyReportBtn = document.getElementById("btn-copy-report-direct");
  const downloadReportBtn = document.getElementById("btn-download-report-direct");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  const modalOverlay = document.getElementById("app-modal");

  if (viewReportBtn) {
    viewReportBtn.addEventListener("click", () => {
      if (!currentScanData) {
        showToast("⚠️ Scan a URL first to generate a security audit report.");
        return;
      }
      const reportText = generateSecurityReportText(currentScanData);
      openModal(
        `📄 Security Audit: ${currentScanData.anatomy.host}`,
        reportText,
        () => {
          copyReportToClipboard(reportText).then(ok => {
            if (ok) showToast("📋 Report copied to clipboard!");
          });
        },
        () => {
          downloadReportAsFile(reportText, currentScanData.anatomy.host);
          showToast("💾 Security report downloaded.");
        }
      );
    });
  }

  if (copyReportBtn) {
    copyReportBtn.addEventListener("click", () => {
      if (!currentScanData) return showToast("⚠️ Scan a URL first.");
      const text = generateSecurityReportText(currentScanData);
      copyReportToClipboard(text).then(ok => {
        if (ok) showToast("📋 Report copied to clipboard!");
      });
    });
  }

  if (downloadReportBtn) {
    downloadReportBtn.addEventListener("click", () => {
      if (!currentScanData) return showToast("⚠️ Scan a URL first.");
      const text = generateSecurityReportText(currentScanData);
      downloadReportAsFile(text, currentScanData.anatomy.host);
      showToast("💾 Security report downloaded as text file.");
    });
  }

  if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeModal);
  if (modalOverlay) {
    modalOverlay.addEventListener("click", (e) => {
      if (e.target === modalOverlay) closeModal();
    });
  }

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
}

// =============================================================================
// 6. URL COMPARISON MODE
// =============================================================================
function setupComparisonMode() {
  const inputA = document.getElementById("compare-url-a");
  const inputB = document.getElementById("compare-url-b");
  const runBtn = document.getElementById("btn-run-comparison");
  const preset1 = document.getElementById("btn-preset-compare-1");
  const preset2 = document.getElementById("btn-preset-compare-2");
  const resultsWrap = document.getElementById("comparison-results-wrap");
  const tbody = document.getElementById("comparison-tbody");
  const headerA = document.getElementById("col-header-a");
  const headerB = document.getElementById("col-header-b");

  if (preset1) {
    preset1.addEventListener("click", () => {
      inputA.value = sampleComparisonPairs[0].urlA;
      inputB.value = sampleComparisonPairs[0].urlB;
      executeComparison();
    });
  }

  if (preset2) {
    preset2.addEventListener("click", () => {
      inputA.value = sampleComparisonPairs[1].urlA;
      inputB.value = sampleComparisonPairs[1].urlB;
      executeComparison();
    });
  }

  if (runBtn) {
    runBtn.addEventListener("click", executeComparison);
  }

  function executeComparison() {
    const urlA = inputA.value.trim();
    const urlB = inputB.value.trim();

    if (!urlA || !urlB) {
      showToast("⚠️ Please enter both URL A and URL B to compare.");
      return;
    }

    const comp = compareUrls(urlA, urlB);
    if (!comp.resultA.valid) {
      showToast(`⚠️ URL A invalid: ${comp.resultA.error}`);
      return;
    }
    if (!comp.resultB.valid) {
      showToast(`⚠️ URL B invalid: ${comp.resultB.error}`);
      return;
    }

    const matrix = buildComparisonMatrix(comp.resultA, comp.resultB);

    if (headerA) headerA.textContent = `URL A: ${comp.resultA.anatomy.host}`;
    if (headerB) headerB.textContent = `URL B: ${comp.resultB.anatomy.host}`;

    let html = "";
    for (const row of matrix) {
      const clsA = `cell-${row.statusA}`;
      const clsB = `cell-${row.statusB}`;
      html += `
        <tr>
          <td class="feature-col"><strong>${escapeHtml(row.feature)}</strong></td>
          <td class="val-col ${clsA}">${escapeHtml(row.valA)}</td>
          <td class="val-col ${clsB}">${escapeHtml(row.valB)}</td>
        </tr>
      `;
    }

    if (tbody) tbody.innerHTML = html;
    if (resultsWrap) resultsWrap.style.display = "block";

    showToast("⚖️ URL comparison complete.");
  }
}

// =============================================================================
// 7. DETECTION TEST LAB
// =============================================================================
function setupTestLab() {
  const runBtn = document.getElementById("btn-run-testlab");
  const summaryGrid = document.getElementById("testlab-summary-chips");
  const table = document.getElementById("testlab-results-table");
  const tbody = document.getElementById("testlab-tbody");

  const totalEl = document.getElementById("test-total-val");
  const passedEl = document.getElementById("test-passed-val");
  const failedEl = document.getElementById("test-failed-val");
  const rateEl = document.getElementById("test-rate-val");
  const timeEl = document.getElementById("test-time-val");

  if (!runBtn) return;

  runBtn.addEventListener("click", () => {
    const report = runTestSuite();

    if (totalEl) totalEl.textContent = report.totalTests;
    if (passedEl) passedEl.textContent = report.passedCount;
    if (failedEl) failedEl.textContent = report.failedCount;
    if (rateEl) rateEl.textContent = `${report.passRate}%`;
    if (timeEl) timeEl.textContent = `${report.totalTimeMs} ms`;

    let html = "";
    for (const r of report.results) {
      const badge = r.passed 
        ? `<span class="badge-low">PASS</span>` 
        : `<span class="badge-high">FAIL</span>`;
      const cleanInput = r.input.length > 40 ? `${r.input.slice(0, 38)}...` : r.input;

      html += `
        <tr>
          <td><code>${escapeHtml(r.id)}</code></td>
          <td><strong>${escapeHtml(r.name)}</strong></td>
          <td><code title="${escapeHtml(r.input)}">${escapeHtml(cleanInput || '(empty)')}</code></td>
          <td><small>${escapeHtml(r.expected)}</small></td>
          <td><small>${escapeHtml(r.actual)}</small></td>
          <td>${badge}</td>
          <td><small>${r.durationMs}ms</small></td>
        </tr>
      `;
    }

    if (tbody) tbody.innerHTML = html;
    if (summaryGrid) summaryGrid.style.display = "grid";
    if (table) table.style.display = "table";

    showToast(`🧪 Test suite finished: ${report.passRate}% pass rate in ${report.totalTimeMs}ms`);
  });
}

// =============================================================================
// 8. SCAN HISTORY & STATISTICS
// =============================================================================
function setupHistoryAndStats() {
  const searchInput = document.getElementById("history-search-input");
  const filterSelect = document.getElementById("history-risk-filter");
  const exportBtn = document.getElementById("btn-export-csv");
  const clearBtn = document.getElementById("btn-clear-history");

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderHistoryTable(filterHistory(searchInput.value, filterSelect ? filterSelect.value : "ALL"));
    });
  }

  if (filterSelect) {
    filterSelect.addEventListener("change", () => {
      renderHistoryTable(filterHistory(searchInput ? searchInput.value : "", filterSelect.value));
    });
  }

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const res = exportHistoryAsCsv();
      if (res.success) {
        showToast(`📥 Exported ${res.count} scan records to CSV.`);
      } else {
        showToast(`⚠️ ${res.message}`);
      }
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (confirm("Are you sure you want to clear all scan history from this browser?")) {
        clearHistory();
        refreshHistoryAndStats();
        showToast("🗑 Scan history cleared.");
      }
    });
  }
}

/**
 * Re-reads history from localStorage, updates summary cards, insights, and history table.
 */
function refreshHistoryAndStats() {
  const stats = calculateStatistics();

  const totalEl = document.getElementById("stat-total-scans");
  const safeEl = document.getElementById("stat-safe-count");
  const suspEl = document.getElementById("stat-suspicious-count");
  const phishEl = document.getElementById("stat-phishing-count");
  const avgRiskEl = document.getElementById("stat-avg-risk");
  const avgSafetyEl = document.getElementById("stat-avg-safety");

  if (totalEl) totalEl.textContent = stats.totalScans;
  if (safeEl) safeEl.textContent = stats.safeCount;
  if (suspEl) suspEl.textContent = stats.suspiciousCount;
  if (phishEl) phishEl.textContent = stats.phishingCount;
  if (avgRiskEl) avgRiskEl.textContent = stats.averageRiskScore;
  if (avgSafetyEl) avgSafetyEl.textContent = `${stats.averageSafetyPercentage}%`;

  // Render Detection Insights
  renderDetectionInsights(stats.detectionInsights, stats.totalScans);

  // Render History Table
  renderHistoryTable(getHistory());
}

/**
 * Renders the Detection Insights list calculated from real history.
 */
function renderDetectionInsights(insights, totalScans) {
  const container = document.getElementById("detection-insights-list");
  if (!container) return;

  if (insights.length === 0) {
    container.innerHTML = `
      <div style="font-size: 0.88rem; color: var(--color-text-dim); padding: 1rem; text-align: center;">
        No indicator occurrences recorded yet. Scan suspicious URLs to see top triggered security heuristics.
      </div>
    `;
    return;
  }

  let html = "";
  const maxOccurrences = Math.max(...insights.map(i => i.count), 1);

  insights.slice(0, 7).forEach((ins, idx) => {
    const percentWidth = Math.round((ins.count / maxOccurrences) * 100);
    html += `
      <div class="insight-item">
        <div class="insight-rank-num">#${idx + 1}</div>
        <div style="width: 220px; font-weight: 600; font-size: 0.85rem; color: var(--color-text-main);">
          ${escapeHtml(ins.name)}
        </div>
        <div class="insight-bar-bg">
          <div class="insight-bar-fill" style="width: ${percentWidth}%;"></div>
        </div>
        <div style="font-size: 0.82rem; color: var(--color-text-muted); font-family: var(--font-mono); white-space: nowrap;">
          <strong>${ins.count}</strong> scans (${ins.percentageOfScans}%)
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

/**
 * Renders the History table.
 */
function renderHistoryTable(records) {
  const tbody = document.getElementById("history-tbody");
  if (!tbody) return;

  if (records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--color-text-dim); padding: 1.5rem;">
          No scan records found matching filter.
        </td>
      </tr>
    `;
    return;
  }

  let html = "";
  for (const r of records) {
    const formattedDate = new Date(r.analyzedAt).toLocaleDateString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    const cleanUrl = r.url.length > 36 ? `${r.url.slice(0, 34)}...` : r.url;

    html += `
      <tr>
        <td><small style="color: var(--color-text-dim);">${escapeHtml(formattedDate)}</small></td>
        <td><strong title="${escapeHtml(r.url)}">${escapeHtml(cleanUrl)}</strong></td>
        <td><span style="font-weight: 700; color: var(--color-accent);">${r.safetyPercentage}%</span></td>
        <td><code>${r.riskScore}/100</code></td>
        <td><span class="${escapeHtml(r.badgeClass)}">${escapeHtml(r.riskLevelLabel)}</span></td>
        <td><small>${escapeHtml(r.classification)}</small></td>
        <td><small style="color: var(--color-text-dim);">${r.triggeredChecksCount} triggers</small></td>
        <td>
          <button type="button" class="btn-secondary btn-load-scan" data-url="${escapeHtml(r.url)}" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" title="Re-scan this URL">
            Load
          </button>
          <button type="button" class="btn-icon-danger btn-del-scan" data-id="${escapeHtml(r.id)}" title="Delete record">
            ✕
          </button>
        </td>
      </tr>
    `;
  }

  tbody.innerHTML = html;

  // Bind dynamic buttons
  tbody.querySelectorAll(".btn-load-scan").forEach(btn => {
    btn.addEventListener("click", () => {
      const url = btn.getAttribute("data-url");
      // Switch to scanner tab
      document.querySelector('[data-tab="tab-scanner"]').click();
      executeScan(url);
    });
  });

  tbody.querySelectorAll(".btn-del-scan").forEach(btn => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-id");
      deleteScan(id);
      refreshHistoryAndStats();
      showToast("Record deleted.");
    });
  });
}

// =============================================================================
// 9. SPOT THE PHISH QUIZ
// =============================================================================
function setupQuiz() {
  const container = document.getElementById("quiz-container");
  const scoreNumEl = document.getElementById("quiz-score-num");
  if (!container) return;

  const questions = pblContent.quiz;
  let userScore = 0;
  const answered = {};

  let html = "";
  questions.forEach((q, qIndex) => {
    html += `
      <div class="quiz-card" id="quiz-card-${q.id}">
        <div style="font-weight: 700; font-size: 1rem; color: var(--color-text-main); margin-bottom: 0.5rem;">
          Question ${qIndex + 1}: ${escapeHtml(q.question)}
        </div>
        <div class="quiz-scenario-box">
          ${escapeHtml(q.scenario)}
        </div>
        <div class="quiz-options-group">
          ${q.options.map((opt, optIndex) => `
            <button type="button" class="quiz-option-btn" data-qid="${q.id}" data-opt="${optIndex}">
              ${String.fromCharCode(65 + optIndex)}. ${escapeHtml(opt)}
            </button>
          `).join("")}
        </div>
        <div class="quiz-explanation-box" id="quiz-exp-${q.id}">
          <strong>💡 Security Analysis:</strong> ${escapeHtml(q.explanation)}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  // Bind option clicks
  container.querySelectorAll(".quiz-option-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const qid = btn.getAttribute("data-qid");
      const optIndex = parseInt(btn.getAttribute("data-opt"), 10);

      if (answered[qid]) return; // already answered
      answered[qid] = true;

      const q = questions.find(item => item.id === qid);
      const isCorrect = optIndex === q.correctIndex;

      if (isCorrect) {
        userScore++;
        btn.classList.add("correct");
        showToast("✔ Correct answer!");
      } else {
        btn.classList.add("wrong");
        // Highlight correct button
        const correctBtn = container.querySelector(`.quiz-option-btn[data-qid="${qid}"][data-opt="${q.correctIndex}"]`);
        if (correctBtn) correctBtn.classList.add("correct");
        showToast("✖ Incorrect choice.");
      }

      // Disable other buttons for this question
      container.querySelectorAll(`.quiz-option-btn[data-qid="${qid}"]`).forEach(b => {
        b.disabled = true;
      });

      // Show explanation
      const expBox = document.getElementById(`quiz-exp-${qid}`);
      if (expBox) expBox.style.display = "block";

      if (scoreNumEl) scoreNumEl.textContent = userScore;
    });
  });
}

// =============================================================================
// 10. PBL PROGRESS REVIEW-II REPORT RENDERER
// =============================================================================
function renderPblSections() {
  const container = document.getElementById("pbl-full-sections-wrap");
  if (!container) return;

  const p = pblContent;

  // Run dynamic evaluation on sample URLs to compute REAL current partial results!
  const demoSafe = analyzeUrl("https://www.wikipedia.org");
  const scoreSafe = calculateRiskAndSafety(demoSafe.checks, demoSafe.anatomy);

  const demoSusp = analyzeUrl("http://example-bank-login.example.test/");
  const scoreSusp = calculateRiskAndSafety(demoSusp.checks, demoSusp.anatomy);

  const demoPhish = analyzeUrl("http://192.168.10.5:8080/secure/login/verify-account.php");
  const scorePhish = calculateRiskAndSafety(demoPhish.checks, demoPhish.anatomy);

  let html = `
    <!-- 1. Introduction -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.introduction.title)}</h3>
      <p style="color: var(--color-accent); font-weight: 600; margin-bottom: 0.75rem;">${escapeHtml(p.introduction.summary)}</p>
      ${p.introduction.paragraphs.map(para => `<p style="color: var(--color-text-muted); margin-bottom: 0.5rem; line-height: 1.6;">${escapeHtml(para)}</p>`).join("")}
    </div>

    <!-- 2. Motivation & Need -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.motivation.title)}</h3>
      <div class="anatomy-grid" style="margin-top: 1rem;">
        ${p.motivation.points.map(pt => `
          <div class="anatomy-block">
            <div class="anatomy-label" style="color: var(--color-accent);">${escapeHtml(pt.heading)}</div>
            <p style="font-size: 0.85rem; color: var(--color-text-muted); margin-top: 0.35rem;">${escapeHtml(pt.text)}</p>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 3. Objectives -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.objectives.title)}</h3>
      <ul style="padding-left: 1.25rem; margin-top: 0.75rem; color: var(--color-text-muted);">
        ${p.objectives.items.map(item => `<li style="margin-bottom: 0.4rem;">${escapeHtml(item)}</li>`).join("")}
      </ul>
    </div>

    <!-- 4. Literature Survey -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.literatureSurvey.title)}</h3>
      <div style="font-size: 0.8rem; color: var(--color-text-dim); margin-bottom: 1rem;">${escapeHtml(p.literatureSurvey.note)}</div>
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        ${p.literatureSurvey.papers.map(paper => `
          <div style="background: var(--color-bg-surface); padding: 1rem; border-radius: var(--radius-md); border-left: 3px solid var(--color-accent);">
            <div style="font-weight: 700; color: var(--color-text-main); font-size: 0.9rem; margin-bottom: 0.25rem;">
              ${escapeHtml(paper.citation)}
            </div>
            <p style="font-size: 0.85rem; color: var(--color-text-muted); line-height: 1.5;">${escapeHtml(paper.finding)}</p>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 5. Problem Statement -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.problemStatement.title)}</h3>
      <div class="clean-status-box" style="background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.3);">
        <div style="font-size: 1.8rem;">⚠️</div>
        <p style="font-size: 0.9rem; color: var(--color-text-muted); line-height: 1.6;">${escapeHtml(p.problemStatement.statement)}</p>
      </div>
    </div>

    <!-- 6. Proposed Solution -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.solutionProposed.title)}</h3>
      <p style="font-size: 0.9rem; color: var(--color-text-muted); line-height: 1.6;">${escapeHtml(p.solutionProposed.overview)}</p>
    </div>

    <!-- 7. Approach & Methodology -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.methodology.title)}</h3>
      <div style="display: flex; flex-direction: column; gap: 0.75rem; margin-top: 1rem;">
        ${p.methodology.steps.map(s => `
          <div style="background: var(--color-bg-surface); padding: 0.9rem 1.1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
            <strong style="color: var(--color-accent);">${escapeHtml(s.step)}</strong>
            <p style="font-size: 0.85rem; color: var(--color-text-muted); margin-top: 0.25rem;">${escapeHtml(s.detail)}</p>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 8. System Architecture (Visual HTML / SVG Diagram) -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.systemArchitecture.title)}</h3>
      <p style="font-size: 0.88rem; color: var(--color-text-muted); margin-bottom: 1rem;">${escapeHtml(p.systemArchitecture.description)}</p>
      
      <!-- Visual SVG Flow Architecture Diagram -->
      <div class="architecture-svg-wrap">
        <svg viewBox="0 0 960 480" width="100%" height="auto" style="max-width: 920px; font-family: system-ui, sans-serif;">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8"/>
            </marker>
            <linearGradient id="boxGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#0e172a"/>
              <stop offset="100%" stop-color="#1e293b"/>
            </linearGradient>
          </defs>

          <!-- Row 1: Input to Features -->
          <rect x="40" y="30" width="160" height="60" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="120" y="65" fill="#f8fafc" font-size="13" font-weight="700" text-anchor="middle">1. User URL Input</text>

          <line x1="200" y1="60" x2="270" y2="60" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="270" y="30" width="180" height="60" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="360" y="55" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">2. Input Validation</text>
          <text x="360" y="73" fill="#94a3b8" font-size="10" text-anchor="middle">Trim &lt;= 2048 chars</text>

          <line x1="450" y1="60" x2="520" y2="60" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="520" y="30" width="180" height="60" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="610" y="55" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">3. URL Parser</text>
          <text x="610" y="73" fill="#94a3b8" font-size="10" text-anchor="middle">RFC 3986 Anatomy</text>

          <line x1="700" y1="60" x2="770" y2="60" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="770" y="30" width="150" height="60" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="845" y="55" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">4. Features</text>
          <text x="845" y="73" fill="#94a3b8" font-size="10" text-anchor="middle">Length, IP, Ratios</text>

          <!-- Down Arrow to Row 2 -->
          <line x1="845" y1="90" x2="845" y2="150" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <!-- Row 2: Detection & Scoring -->
          <rect x="700" y="150" width="220" height="70" rx="8" fill="url(#boxGrad)" stroke="#f59e0b" stroke-width="2"/>
          <text x="810" y="180" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">5. 15+ Rule Checks</text>
          <text x="810" y="200" fill="#f59e0b" font-size="10" text-anchor="middle">Heuristic Detection Engine</text>

          <line x1="700" y1="185" x2="630" y2="185" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="420" y="150" width="210" height="70" rx="8" fill="url(#boxGrad)" stroke="#22c55e" stroke-width="2"/>
          <text x="525" y="180" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">6. Risk Scoring Engine</text>
          <text x="525" y="200" fill="#22c55e" font-size="10" text-anchor="middle">Bounded Sum: 0 - 100 pts</text>

          <line x1="420" y1="185" x2="350" y2="185" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="140" y="150" width="210" height="70" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="245" y="178" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">7. Safety % Calculator</text>
          <text x="245" y="198" fill="#38bdf8" font-size="10" text-anchor="middle">Safety = 100 - Risk Score</text>

          <!-- Down Arrow to Row 3 -->
          <line x1="245" y1="220" x2="245" y2="280" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <!-- Row 3: Classification & Presentation -->
          <rect x="140" y="280" width="210" height="70" rx="8" fill="url(#boxGrad)" stroke="#c084fc" stroke-width="2"/>
          <text x="245" y="308" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">8. Risk Classification</text>
          <text x="245" y="328" fill="#c084fc" font-size="10" text-anchor="middle">LOW / MEDIUM / HIGH</text>

          <line x1="350" y1="315" x2="420" y2="315" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="420" y="280" width="230" height="70" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="535" y="308" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">9. Results &amp; Explainability</text>
          <text x="535" y="328" fill="#94a3b8" font-size="10" text-anchor="middle">Gauge, Triggers &amp; Anatomy</text>

          <line x1="650" y1="315" x2="720" y2="315" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

          <rect x="720" y="280" width="200" height="70" rx="8" fill="url(#boxGrad)" stroke="#38bdf8" stroke-width="2"/>
          <text x="820" y="308" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">10. Persistence &amp; Export</text>
          <text x="820" y="328" fill="#94a3b8" font-size="10" text-anchor="middle">History, Stats &amp; Audit Report</text>
        </svg>
      </div>
    </div>

    <!-- 9. System Modules (All 15 Modules Table) -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.systemModules ? "9. Description of All 15 System Modules" : "9. System Modules")}</h3>
      <div style="overflow-x: auto; margin-top: 1rem;">
        <table class="all-checks-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Module Name</th>
              <th>Purpose</th>
              <th>Inputs &rarr; Processing</th>
              <th>Output</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${p.systemModules.map(m => `
              <tr>
                <td><strong>${m.id}</strong></td>
                <td><strong>${escapeHtml(m.name)}</strong></td>
                <td><small>${escapeHtml(m.purpose)}</small></td>
                <td><small>${escapeHtml(m.inputs)} &rarr; ${escapeHtml(m.processing)}</small></td>
                <td><code style="font-size: 0.75rem;">${escapeHtml(m.output)}</code></td>
                <td><span class="badge-low">${escapeHtml(m.status)}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 10. Requirements Analysis and SRS -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.srs.title)}</h3>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-top: 1rem;">
        <div>
          <h4 style="color: var(--color-accent); font-size: 0.95rem; margin-bottom: 0.5rem;">Functional Requirements (FR)</h4>
          <ul style="font-size: 0.85rem; color: var(--color-text-muted); padding-left: 1.1rem;">
            ${p.srs.functional.map(fr => `<li style="margin-bottom: 0.35rem;">${escapeHtml(fr)}</li>`).join("")}
          </ul>
        </div>
        <div>
          <h4 style="color: var(--color-safe); font-size: 0.95rem; margin-bottom: 0.5rem;">Non-Functional Requirements (NFR)</h4>
          <ul style="font-size: 0.85rem; color: var(--color-text-muted); padding-left: 1.1rem;">
            ${p.srs.nonFunctional.map(nfr => `<li style="margin-bottom: 0.35rem;">${escapeHtml(nfr)}</li>`).join("")}
          </ul>
        </div>
      </div>
      <div style="margin-top: 1.25rem; background: var(--color-bg-surface); padding: 1rem; border-radius: var(--radius-md); font-size: 0.85rem; border: 1px solid var(--color-border);">
        <strong>Hardware &amp; Software Environment:</strong><br>
        <span style="color: var(--color-text-dim);">Hardware: ${escapeHtml(p.srs.specifications.hardwareMin)}</span><br>
        <span style="color: var(--color-text-dim);">Software: ${escapeHtml(p.srs.specifications.softwareMin)}</span><br>
        <span style="color: var(--color-text-dim);">Execution: ${escapeHtml(p.srs.specifications.devEnvironment)}</span>
      </div>
    </div>

    <!-- 11. Code Implementation (50% Milestone) -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.codeImplementation.title)}</h3>
      <p style="font-size: 0.88rem; color: var(--color-text-muted); margin-bottom: 1rem;">${escapeHtml(p.codeImplementation.summary)}</p>
      <div style="display: flex; flex-direction: column; gap: 1rem;">
        ${p.codeImplementation.snippets.map(snip => `
          <div>
            <div style="font-weight: 700; font-size: 0.85rem; color: var(--color-accent); margin-bottom: 0.35rem;">
              ${escapeHtml(snip.name)}
            </div>
            <pre style="background: var(--color-bg-base); border: 1px solid var(--color-border); padding: 0.85rem; border-radius: var(--radius-md); font-size: 0.82rem; overflow-x: auto; color: #38bdf8;"><code>${escapeHtml(snip.code)}</code></pre>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 12. Demonstration of Modules -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.moduleDemonstration.title)}</h3>
      <p style="font-size: 0.88rem; color: var(--color-text-muted); margin-bottom: 0.75rem;">${escapeHtml(p.moduleDemonstration.description)}</p>
      <div class="anatomy-grid">
        ${p.moduleDemonstration.demos.map(d => `
          <div class="anatomy-block">
            <div class="anatomy-label" style="color: var(--color-accent);">${escapeHtml(d.tab)} Module</div>
            <p style="font-size: 0.85rem; color: var(--color-text-muted); margin-top: 0.35rem;">${escapeHtml(d.action)}</p>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 13. Partial Results (LIVE DYNAMIC ENGINE RESULTS) -->
    <div class="analysis-section-card">
      <div class="section-header">
        <div>
          <h3 class="section-title">13. Partial Results (Live Rule-Engine Output)</h3>
          <div class="section-subtitle">Dynamically evaluated results directly from the active analyzer engine on demo samples</div>
        </div>
        <span class="proto-badge">Live Evaluated</span>
      </div>

      <div style="overflow-x: auto;">
        <table class="all-checks-table">
          <thead>
            <tr>
              <th>Evaluation Sample</th>
              <th>Actual Risk Score</th>
              <th>Safety %</th>
              <th>Calculated Risk Level</th>
              <th>Classification</th>
              <th>Triggered Indicators</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Safe: Wikipedia</strong><br><small style="color: var(--color-text-dim);">https://www.wikipedia.org</small></td>
              <td><code>${scoreSafe.riskScore} / 100</code></td>
              <td><span style="color: var(--color-safe); font-weight: 700;">${scoreSafe.safetyPercentage}%</span></td>
              <td><span class="${scoreSafe.badgeClass}">${scoreSafe.riskLevelLabel}</span></td>
              <td><span class="${scoreSafe.classificationBadgeClass}">${scoreSafe.classification}</span></td>
              <td><small>${scoreSafe.triggeredChecks.map(c => c.name).join(", ") || "None (All 15 Passed)"}</small></td>
            </tr>
            <tr>
              <td><strong>Suspicious: Bank Mockup</strong><br><small style="color: var(--color-text-dim);">http://example-bank-login.example.test/</small></td>
              <td><code>${scoreSusp.riskScore} / 100</code></td>
              <td><span style="color: var(--color-warning); font-weight: 700;">${scoreSusp.safetyPercentage}%</span></td>
              <td><span class="${scoreSusp.badgeClass}">${scoreSusp.riskLevelLabel}</span></td>
              <td><span class="${scoreSusp.classificationBadgeClass}">${scoreSusp.classification}</span></td>
              <td><small>${scoreSusp.triggeredChecks.map(c => c.name).join(", ")}</small></td>
            </tr>
            <tr>
              <td><strong>Phishing: IP &amp; Port 8080 Mockup</strong><br><small style="color: var(--color-text-dim);">http://192.168.10.5:8080/secure/login/verify-account.php</small></td>
              <td><code>${scorePhish.riskScore} / 100</code></td>
              <td><span style="color: var(--color-danger); font-weight: 700;">${scorePhish.safetyPercentage}%</span></td>
              <td><span class="${scorePhish.badgeClass}">${scorePhish.riskLevelLabel}</span></td>
              <td><span class="${scorePhish.classificationBadgeClass}">${scorePhish.classification}</span></td>
              <td><small>${scorePhish.triggeredChecks.map(c => c.name).join(", ")}</small></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 14. Conclusion & Future Work -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.conclusion.title)}</h3>
      <p style="font-size: 0.9rem; color: var(--color-text-muted); line-height: 1.6; margin-bottom: 1rem;">
        ${escapeHtml(p.conclusion.conclusionText)}
      </p>
      <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--color-warning); padding: 1rem; border-radius: var(--radius-md); margin-bottom: 1rem;">
        <strong style="color: var(--color-warning);">${escapeHtml(p.conclusion.futureWorkNotice)}</strong>
      </div>
      <div class="anatomy-grid">
        ${p.conclusion.futureWorkItems.map(item => `
          <div class="anatomy-block">
            <div class="anatomy-label" style="color: var(--color-accent);">${escapeHtml(item.name)}</div>
            <p style="font-size: 0.85rem; color: var(--color-text-muted); margin-top: 0.35rem;">${escapeHtml(item.detail)}</p>
          </div>
        `).join("")}
      </div>
    </div>

    <!-- 15. References -->
    <div class="analysis-section-card">
      <h3 class="section-title">${escapeHtml(p.references.title)}</h3>
      <div style="font-size: 0.8rem; color: var(--color-text-dim); margin-bottom: 0.75rem;">
        ${escapeHtml(p.references.citationNote)}
      </div>
      <ol style="padding-left: 1.25rem; font-size: 0.85rem; color: var(--color-text-muted); line-height: 1.6;">
        ${p.references.list.map(ref => `<li style="margin-bottom: 0.5rem;">${escapeHtml(ref)}</li>`).join("")}
      </ol>
    </div>
  `;

  container.innerHTML = html;
}
