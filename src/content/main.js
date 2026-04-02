/**
 * Content script entry point.
 * Orchestrates scanning, overlay rendering, and messaging with the background.
 */

(() => {
  'use strict';

  const browser = globalThis.browser || globalThis.chrome;
  const { MUTATION_DEBOUNCE_MS } = PID_CONSTANTS;

  let allFindings = [];
  let currentThreatLevel = 'clean';
  let highlightsVisible = true;
  let aiWarningVisible = false;

  // -------------------------------------------------------------------------
  // Options loading
  // -------------------------------------------------------------------------

  async function loadOptions() {
    try {
      const result = await browser.storage.sync.get({
        highlightsEnabled: true,
        aiWarningEnabled: false,
        allowlistedDomains: [],
        sensitivity: 'medium',
      });
      highlightsVisible = result.highlightsEnabled;
      aiWarningVisible = result.aiWarningEnabled;
      return result;
    } catch {
      return {
        highlightsEnabled: true,
        aiWarningEnabled: false,
        allowlistedDomains: [],
        sensitivity: 'medium',
      };
    }
  }

  // -------------------------------------------------------------------------
  // Main scan flow
  // -------------------------------------------------------------------------

  async function runFullScan() {
    const options = await loadOptions();

    // Check domain allowlist
    const hostname = window.location.hostname;
    if (options.allowlistedDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
      sendResults([], 'clean');
      return;
    }

    const { findings, threatLevel } = await PID_SCANNER.scanPage();

    // Apply sensitivity filter
    const filtered = filterBySensitivity(findings, options.sensitivity);

    allFindings = filtered;
    currentThreatLevel = PID_THREAT.computePageThreatLevel(filtered);

    sendResults(filtered, currentThreatLevel);

    // Render overlays
    if (filtered.length > 0 && highlightsVisible) {
      PID_OVERLAY.renderHighlights(filtered);
    }

    // AI warning
    if (filtered.length > 0 && aiWarningVisible) {
      PID_OVERLAY.injectAIWarning(filtered.length);
    }
  }

  /**
   * Filter findings based on sensitivity level.
   */
  function filterBySensitivity(findings, sensitivity) {
    const minSeverity = {
      low: 'low',
      medium: 'medium',
      high: 'high',
    }[sensitivity] || 'medium';

    const order = PID_CONSTANTS.SEVERITY_ORDER;
    const threshold = order[minSeverity] || 0;

    return findings.filter(f => (order[f.severity] || 0) >= threshold);
  }

  /**
   * Send scan results to the background service worker.
   */
  function sendResults(findings, threatLevel) {
    try {
      browser.runtime.sendMessage({
        type: 'SCAN_RESULTS',
        data: {
          findings: PID_THREAT.serializeFindings(findings),
          threatLevel,
          url: window.location.href,
          timestamp: Date.now(),
        },
      });
    } catch {
      // Extension context may be invalidated — ignore
    }
  }

  // -------------------------------------------------------------------------
  // MutationObserver for dynamic content
  // -------------------------------------------------------------------------

  let mutationTimer = null;

  function setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      if (mutationTimer) clearTimeout(mutationTimer);
      mutationTimer = setTimeout(() => {
        handleMutations(mutations);
      }, MUTATION_DEBOUNCE_MS);
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  }

  function handleMutations(mutations) {
    const newFindings = [];

    for (const mutation of mutations) {
      if (allFindings.length + newFindings.length >= PID_CONSTANTS.MAX_FINDINGS) break;

      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          newFindings.push(...PID_SCANNER.scanNode(node));
        }
      } else if (mutation.type === 'characterData') {
        newFindings.push(...PID_SCANNER.scanNode(mutation.target));
      }
    }

    if (newFindings.length > 0) {
      allFindings = allFindings.concat(newFindings);
      currentThreatLevel = PID_THREAT.computePageThreatLevel(allFindings);
      sendResults(allFindings, currentThreatLevel);

      if (highlightsVisible) {
        PID_OVERLAY.renderHighlights(allFindings);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Message handling from popup / background
  // -------------------------------------------------------------------------

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
      case 'GET_FINDINGS':
        sendResponse({
          findings: PID_THREAT.serializeFindings(allFindings),
          threatLevel: currentThreatLevel,
        });
        return true;

      case 'TOGGLE_HIGHLIGHTS':
        highlightsVisible = message.visible;
        if (highlightsVisible && allFindings.length > 0) {
          PID_OVERLAY.renderHighlights(allFindings);
        } else {
          PID_OVERLAY.clearHighlights();
        }
        break;

      case 'TOGGLE_AI_WARNING':
        aiWarningVisible = message.visible;
        if (aiWarningVisible && allFindings.length > 0) {
          PID_OVERLAY.injectAIWarning(allFindings.length);
        } else {
          PID_OVERLAY.removeAIWarning();
        }
        break;

      case 'SCROLL_TO_FINDING':
        PID_OVERLAY.scrollToFinding(message.findingId, allFindings);
        break;

      case 'RESCAN':
        runFullScan();
        break;
    }
  });

  // -------------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------------

  runFullScan();
  setupMutationObserver();
})();
