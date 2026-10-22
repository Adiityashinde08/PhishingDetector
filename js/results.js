/**
 * Phishing URL Detector - Results Presentation Renderer
 * 
 * Renders:
 * 1. Prominent Safety Percentage Gauge (e.g., "87% Safe", "32% Safe")
 * 2. Unified Risk Scores, Levels, and Rule Confidence
 * 3. Explainable Risk Breakdown ("Why did we give this result?")
 * 4. Interactive URL Anatomy with suspicious token tagging
 * 5. Complete 15-Rule Security Audit Accordion
 * 6. Tailored Defensive Recommendations
 */

import { updateCircularGauge, escapeHtml } from "./ui.js";

/**
 * Main render function that populates the results panel in index.html.
 * @param {object} scanData - Complete analysis and scoring result
 */
export function renderScanResults(scanData) {
  const panel = document.getElementById("scan-results-panel");
  if (!panel) return;

  const { anatomy, checks, scoring } = scanData;

  // 1. Activate Panel
  panel.classList.add("active");

  // 2. Animate Circular Safety Gauge
  updateCircularGauge(scoring.safetyPercentage, scoring.riskColor);

  // 3. Update Text Scores and Badges
  const riskScoreEl = document.getElementById("val-risk-score");
  const safetyScoreEl = document.getElementById("val-safety-score");
  const riskLevelBadgeEl = document.getElementById("badge-risk-level");
  const classificationBadgeEl = document.getElementById("badge-classification");
  const ruleConfidenceEl = document.getElementById("val-rule-confidence");
  const verdictSummaryEl = document.getElementById("verdict-summary-text");

  if (riskScoreEl) riskScoreEl.textContent = `${scoring.riskScore} / 100`;
  if (safetyScoreEl) safetyScoreEl.textContent = `${scoring.safetyPercentage}%`;
  
  if (riskLevelBadgeEl) {
    riskLevelBadgeEl.className = scoring.badgeClass;
    riskLevelBadgeEl.textContent = scoring.riskLevelLabel;
  }

  if (classificationBadgeEl) {
    classificationBadgeEl.className = scoring.classificationBadgeClass;
    classificationBadgeEl.textContent = scoring.classification;
  }

  if (ruleConfidenceEl) {
    ruleConfidenceEl.textContent = `${scoring.ruleConfidence}%`;
  }

  if (verdictSummaryEl) {
    verdictSummaryEl.textContent = scoring.riskLevelSummary;
  }

  // 4. Render Explainable Risk Breakdown ("Why did the detector give this result?")
  renderRiskBreakdown(scoring.triggeredChecks, scoring.riskScore);

  // 5. Render Interactive URL Anatomy
  renderUrlAnatomy(anatomy, scanData.inputUrl);

  // 6. Render All 15 Checks Table
  renderAllChecksTable(checks);

  // 7. Render Contextual Recommended Action
  renderRecommendedAction(scoring.recommendedAction, scoring.riskLevelKey);

  // Smoothly scroll results into view
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Renders the explainable trigger list.
 */
function renderRiskBreakdown(triggeredChecks, totalRiskScore) {
  const container = document.getElementById("risk-breakdown-list");
  const totalPointsEl = document.getElementById("breakdown-total-pts");
  if (!container) return;

  if (totalPointsEl) {
    totalPointsEl.textContent = `Total Risk Contribution: ${totalRiskScore} / 100 pts`;
  }

  if (triggeredChecks.length === 0) {
    container.innerHTML = `
      <div class="clean-status-box">
        <div class="clean-icon">🛡</div>
        <div>
          <h5 style="color: var(--color-safe); margin-bottom: 0.25rem;">Clean URL Heuristic Signature</h5>
          <p style="font-size: 0.88rem; color: var(--color-text-muted);">
            No major suspicious indicators or known deception patterns were triggered. 
            The URL conforms to standard lexical domain naming practices and utilizes HTTPS encryption.
          </p>
        </div>
      </div>
    `;
    return;
  }

  let html = "";
  for (const check of triggeredChecks) {
    const sevClass = check.severity === "HIGH" ? "high" : check.severity === "MEDIUM" ? "medium" : "low";
    html += `
      <div class="trigger-item ${sevClass}">
        <div class="trigger-info">
          <h5>
            <span>${escapeHtml(check.name)}</span>
            <span class="badge-${check.severity.toLowerCase()}">${check.severity}</span>
          </h5>
          <p>${escapeHtml(check.explanation)}</p>
          <small>🔬 Technical Detail: ${escapeHtml(check.detail)}</small>
        </div>
        <div class="trigger-pts-badge">+${check.points} pts</div>
      </div>
    `;
  }

  container.innerHTML = html;
}

/**
 * Renders the URL Anatomy decomposition grid and interactive tokenized highlight string.
 */
function renderUrlAnatomy(anatomy, rawInput) {
  const gridContainer = document.getElementById("anatomy-cards-grid");
  const tokenBar = document.getElementById("anatomy-token-bar");

  if (gridContainer) {
    gridContainer.innerHTML = `
      <div class="anatomy-block ${anatomy.protocol === 'http:' ? 'flagged' : ''}">
        <div class="anatomy-label">Protocol / Scheme</div>
        <div class="anatomy-value">${escapeHtml(anatomy.protocol)}</div>
        ${anatomy.protocol === 'http:' ? '<div class="anatomy-flag-pill">Unencrypted HTTP</div>' : ''}
      </div>

      <div class="anatomy-block ${anatomy.isIpHost ? 'flagged' : ''}">
        <div class="anatomy-label">Host Domain / IP</div>
        <div class="anatomy-value">${escapeHtml(anatomy.host)}</div>
        ${anatomy.isIpHost ? '<div class="anatomy-flag-pill">Raw IP Address</div>' : ''}
      </div>

      <div class="anatomy-block">
        <div class="anatomy-label">Registered Root Domain</div>
        <div class="anatomy-value">${escapeHtml(anatomy.registeredDomain)}</div>
      </div>

      <div class="anatomy-block ${anatomy.subdomainCount >= 3 ? 'flagged' : ''}">
        <div class="anatomy-label">Subdomains (${anatomy.subdomainCount})</div>
        <div class="anatomy-value">${escapeHtml(anatomy.subdomain || '(None)')}</div>
        ${anatomy.subdomainCount >= 3 ? '<div class="anatomy-flag-pill">Deep Subdomain Nesting</div>' : ''}
      </div>

      <div class="anatomy-block ${anatomy.explicitPort && anatomy.explicitPort !== '80' && anatomy.explicitPort !== '443' ? 'flagged' : ''}">
        <div class="anatomy-label">Port Destination</div>
        <div class="anatomy-value">${escapeHtml(anatomy.port)} ${anatomy.explicitPort ? `(Explicit :${anatomy.explicitPort})` : '(Default)'}</div>
        ${anatomy.explicitPort && anatomy.explicitPort !== '80' && anatomy.explicitPort !== '443' ? '<div class="anatomy-flag-pill">Unusual Custom Port</div>' : ''}
      </div>

      <div class="anatomy-block">
        <div class="anatomy-label">Path Segment</div>
        <div class="anatomy-value">${escapeHtml(anatomy.pathname || '/')}</div>
      </div>

      <div class="anatomy-block">
        <div class="anatomy-label">Query Parameters</div>
        <div class="anatomy-value">${escapeHtml(anatomy.search || '(None)')}</div>
      </div>

      <div class="anatomy-block ${anatomy.totalLength > 75 ? 'flagged' : ''}">
        <div class="anatomy-label">Total URL Length</div>
        <div class="anatomy-value">${anatomy.totalLength} characters</div>
        ${anatomy.totalLength > 75 ? '<div class="anatomy-flag-pill">Excessive Length</div>' : ''}
      </div>
    `;
  }

  // Interactive tokenized visual bar
  if (tokenBar) {
    const isHttp = anatomy.protocol === "http:";
    const hasAt = anatomy.rawUrl.includes("@");

    let tokensHtml = `
      <span class="anatomy-token ${isHttp ? 'token-flagged' : 'token-proto'}" title="Protocol">${escapeHtml(anatomy.protocol)}//</span>
    `;

    if (anatomy.subdomain) {
      tokensHtml += `<span class="anatomy-token token-sub" title="Subdomain">${escapeHtml(anatomy.subdomain)}.</span>`;
    }

    tokensHtml += `<span class="anatomy-token ${anatomy.isIpHost ? 'token-flagged' : 'token-domain'}" title="Host Domain">${escapeHtml(anatomy.isIpHost ? anatomy.host : anatomy.registeredDomain)}</span>`;

    if (anatomy.explicitPort) {
      tokensHtml += `<span class="anatomy-token token-flagged" title="Custom Port">:${escapeHtml(anatomy.explicitPort)}</span>`;
    }

    if (anatomy.pathname && anatomy.pathname !== "/") {
      tokensHtml += `<span class="anatomy-token token-path" title="Path Segment">${escapeHtml(anatomy.pathname)}</span>`;
    }

    if (anatomy.search) {
      tokensHtml += `<span class="anatomy-token token-query" title="Query String">${escapeHtml(anatomy.search)}</span>`;
    }

    if (anatomy.hash) {
      tokensHtml += `<span class="anatomy-token" title="Fragment">${escapeHtml(anatomy.hash)}</span>`;
    }

    tokenBar.innerHTML = tokensHtml;
  }
}

/**
 * Renders the complete 15-rule security checks table.
 */
function renderAllChecksTable(checks) {
  const tbody = document.getElementById("all-checks-tbody");
  if (!tbody) return;

  let html = "";
  for (const c of checks) {
    const statusBadge = c.triggered
      ? `<span class="badge-high">TRIGGERED</span>`
      : `<span class="badge-low">PASSED</span>`;
    
    html += `
      <tr>
        <td><strong>${escapeHtml(c.name)}</strong></td>
        <td>${statusBadge}</td>
        <td><code>+${c.points} pts</code></td>
        <td><small>${escapeHtml(c.explanation)}</small></td>
        <td><small style="color: var(--color-accent); font-family: var(--font-mono);">${escapeHtml(c.detail)}</small></td>
      </tr>
    `;
  }

  tbody.innerHTML = html;
}

/**
 * Renders the recommended defensive action.
 */
function renderRecommendedAction(actionText, riskLevelKey) {
  const textEl = document.getElementById("recommended-action-text");
  const iconEl = document.getElementById("recommended-action-icon");
  if (!textEl) return;

  textEl.textContent = actionText;

  if (iconEl) {
    if (riskLevelKey === "LOW") iconEl.textContent = "🛡";
    else if (riskLevelKey === "MEDIUM") iconEl.textContent = "⚠️";
    else iconEl.textContent = "🚨";
  }
}
