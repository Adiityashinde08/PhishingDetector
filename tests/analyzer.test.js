/**
 * Standalone Automated Test Runner for Phishing URL Detector
 * Can be run in browser (via tests.html) or automated environments.
 */

import { runTestSuite } from "../js/testLab.js";

export function executeAndRenderTests(containerId = "test-output") {
  const container = document.getElementById(containerId);
  if (!container) return;

  const testReport = runTestSuite();

  let html = `
    <div class="test-summary-header">
      <div class="metric-chip">
        <span class="label">Total Tests:</span>
        <span class="value">${testReport.totalTests}</span>
      </div>
      <div class="metric-chip pass">
        <span class="label">Passed:</span>
        <span class="value">${testReport.passedCount}</span>
      </div>
      <div class="metric-chip ${testReport.failedCount > 0 ? 'fail' : ''}">
        <span class="label">Failed:</span>
        <span class="value">${testReport.failedCount}</span>
      </div>
      <div class="metric-chip rate">
        <span class="label">Rule-Engine Pass Rate:</span>
        <span class="value">${testReport.passRate}%</span>
      </div>
      <div class="metric-chip time">
        <span class="label">Total Time:</span>
        <span class="value">${testReport.totalTimeMs} ms</span>
      </div>
    </div>

    <div class="test-disclaimer-box">
      <strong>Important PBL Note:</strong> This metric represents the <em>rule-engine test-suite pass rate</em> across 
      controlled edge cases and synthetic unit tests. It is <strong>NOT</strong> real-world phishing detection accuracy.
    </div>

    <table class="test-results-table">
      <thead>
        <tr>
          <th>Test ID</th>
          <th>Test Name</th>
          <th>Input URL</th>
          <th>Expected Heuristic</th>
          <th>Actual Result</th>
          <th>Status</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
  `;

  for (const r of testReport.results) {
    const statusClass = r.passed ? "badge-pass" : "badge-fail";
    const statusText = r.passed ? "PASS" : "FAIL";
    const cleanInput = r.input.length > 50 ? `${r.input.slice(0, 48)}...` : r.input;

    html += `
      <tr class="${r.passed ? 'row-pass' : 'row-fail'}">
        <td><code>${r.id}</code></td>
        <td><strong>${r.name}</strong></td>
        <td><code class="input-code" title="${r.input}">${cleanInput || '<em>(empty)</em>'}</code></td>
        <td><small>${r.expected}</small></td>
        <td><small>${r.actual}</small></td>
        <td><span class="test-badge ${statusClass}">${statusText}</span></td>
        <td><small>${r.durationMs}ms</small></td>
      </tr>
    `;
  }

  html += `
      </tbody>
    </table>
  `;

  container.innerHTML = html;
  return testReport;
}
