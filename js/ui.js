/**
 * Phishing URL Detector - UI Helpers & Component Utilities
 */

/**
 * Escapes unsafe HTML characters to prevent XSS injection in dynamic DOM rendering.
 * @param {string} str 
 * @returns {string} Sanitized string
 */
export function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Displays a transient toast notification in the bottom right corner.
 * @param {string} message 
 * @param {number} durationMs 
 */
export function showToast(message, durationMs = 2800) {
  let toast = document.getElementById("app-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "app-toast";
    toast.className = "toast-notice";
    document.body.appendChild(toast);
  }

  toast.textContent = message;
  toast.classList.add("show");

  if (toast._timer) clearTimeout(toast._timer);
  toast._timer = setTimeout(() => {
    toast.classList.remove("show");
  }, durationMs);
}

/**
 * Updates the circular SVG gauge visual and animated stroke offset.
 * @param {number} percentage - 0 to 100
 * @param {string} colorCssVar - CSS color variable or hex
 */
export function updateCircularGauge(percentage, colorCssVar) {
  const meterCircle = document.getElementById("gauge-meter");
  const numberText = document.getElementById("gauge-percentage-val");
  const verdictBanner = document.getElementById("verdict-banner");

  if (!meterCircle || !numberText) return;

  const radius = 80;
  const circumference = 2 * Math.PI * radius; // ~502.65

  meterCircle.style.strokeDasharray = `${circumference} ${circumference}`;
  const clamped = Math.max(0, Math.min(100, percentage));
  const offset = circumference - (clamped / 100) * circumference;

  meterCircle.style.strokeDashoffset = offset;
  meterCircle.style.stroke = colorCssVar;

  if (verdictBanner) {
    verdictBanner.style.setProperty("--verdict-color", colorCssVar);
  }

  // Smooth number count animation
  let currentVal = 0;
  const duration = 600;
  const frameRate = 1000 / 60;
  const totalFrames = Math.round(duration / frameRate);
  let frame = 0;

  const counterInterval = setInterval(() => {
    frame++;
    const progress = frame / totalFrames;
    currentVal = Math.round(clamped * progress);
    numberText.textContent = `${currentVal}%`;

    if (frame >= totalFrames) {
      numberText.textContent = `${clamped}%`;
      clearInterval(counterInterval);
    }
  }, frameRate);
}

/**
 * Opens the universal modal window with title and preformatted content.
 * @param {string} title 
 * @param {string} contentText 
 * @param {Function} onCopy 
 * @param {Function} onDownload 
 */
export function openModal(title, contentText, onCopy, onDownload) {
  const overlay = document.getElementById("app-modal");
  const titleEl = document.getElementById("modal-title");
  const bodyEl = document.getElementById("modal-body");
  const copyBtn = document.getElementById("modal-copy-btn");
  const downloadBtn = document.getElementById("modal-download-btn");

  if (!overlay || !bodyEl) return;

  if (titleEl) titleEl.textContent = title;
  bodyEl.textContent = contentText;

  if (copyBtn && onCopy) {
    copyBtn.onclick = onCopy;
  }
  if (downloadBtn && onDownload) {
    downloadBtn.onclick = onDownload;
  }

  overlay.classList.add("active");
  document.body.style.overflow = "hidden";
}

/**
 * Closes the modal window.
 */
export function closeModal() {
  const overlay = document.getElementById("app-modal");
  if (overlay) {
    overlay.classList.remove("active");
    document.body.style.overflow = "";
  }
}
