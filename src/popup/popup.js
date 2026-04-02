/**
 * Popup UI — fetches findings from background/content and renders the report.
 */

(() => {
  'use strict';

  const browser = globalThis.browser || globalThis.chrome;

  const FINDING_TYPE_LABELS = {
    'invisible-unicode': 'Invisible Characters',
    'css-hidden': 'Hidden Content',
    'html-suspicious': 'Suspicious HTML',
  };

  const THREAT_LEVEL_LABELS = {
    clean: 'No threats detected',
    suspicious: 'Suspicious content found',
    malicious: 'Prompt injection detected',
  };

  // -------------------------------------------------------------------------
  // DOM references
  // -------------------------------------------------------------------------

  const statusEl = document.getElementById('status');
  const statusLevelEl = document.getElementById('status-level');
  const statusDetailEl = document.getElementById('status-detail');
  const controlsEl = document.getElementById('controls');
  const findingsContainerEl = document.getElementById('findings-container');
  const toggleHighlightsEl = document.getElementById('toggle-highlights');
  const toggleAiWarningEl = document.getElementById('toggle-ai-warning');
  const rescanBtn = document.getElementById('rescan-btn');
  const optionsLink = document.getElementById('options-link');

  // -------------------------------------------------------------------------
  // Fetch and render
  // -------------------------------------------------------------------------

  async function init() {
    // Load saved toggle states
    try {
      const opts = await browser.storage.sync.get({
        highlightsEnabled: true,
        aiWarningEnabled: false,
      });
      toggleHighlightsEl.checked = opts.highlightsEnabled;
      toggleAiWarningEl.checked = opts.aiWarningEnabled;
    } catch { /* defaults */ }

    // Fetch results
    try {
      const response = await browser.runtime.sendMessage({ type: 'GET_TAB_RESULTS' });
      render(response);
    } catch {
      render({ findings: [], threatLevel: 'clean' });
    }
  }

  function render({ findings, threatLevel }) {
    // Update status
    statusEl.className = `status status-${threatLevel}`;
    statusLevelEl.textContent = THREAT_LEVEL_LABELS[threatLevel] || 'Unknown';

    if (findings.length === 0) {
      statusDetailEl.textContent = 'Page appears clean';
    } else {
      statusDetailEl.textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''} detected`;
    }

    // Show controls if there are findings
    controlsEl.style.display = findings.length > 0 ? '' : 'none';

    // Render findings
    renderFindings(findings);
  }

  function renderFindings(findings) {
    findingsContainerEl.innerHTML = '';

    if (findings.length === 0) {
      findingsContainerEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">\u2705</div>
          <div>No prompt injection patterns found on this page.</div>
        </div>
      `;
      return;
    }

    // Group by type
    const groups = {};
    for (const f of findings) {
      if (!groups[f.type]) groups[f.type] = [];
      groups[f.type].push(f);
    }

    // Render groups in priority order
    const typeOrder = ['invisible-unicode', 'css-hidden', 'html-suspicious'];
    for (const type of typeOrder) {
      const groupFindings = groups[type];
      if (!groupFindings || groupFindings.length === 0) continue;

      const group = document.createElement('div');
      group.className = 'findings-group';

      const header = document.createElement('div');
      header.className = 'findings-group-header';
      header.textContent = `${FINDING_TYPE_LABELS[type] || type} (${groupFindings.length})`;
      group.appendChild(header);

      for (const finding of groupFindings) {
        group.appendChild(createFindingItem(finding));
      }

      findingsContainerEl.appendChild(group);
    }
  }

  function createFindingItem(finding) {
    const item = document.createElement('div');
    item.className = 'finding-item';

    // Severity badge
    const badge = document.createElement('span');
    badge.className = `finding-severity severity-${finding.severity}`;
    badge.textContent = finding.severity;
    item.appendChild(badge);

    // Content
    const content = document.createElement('div');
    content.className = 'finding-content';

    const desc = document.createElement('div');
    desc.className = 'finding-desc';
    desc.textContent = finding.description;
    content.appendChild(desc);

    // Decoded text for tag chars
    if (finding.decodedText) {
      const decoded = document.createElement('div');
      decoded.className = 'finding-decoded';
      decoded.textContent = finding.decodedText;
      content.appendChild(decoded);
    }

    // Snippet
    if (finding.textSnippet) {
      const snippet = document.createElement('div');
      snippet.className = 'finding-snippet';
      snippet.textContent = finding.textSnippet;
      content.appendChild(snippet);
    }

    item.appendChild(content);

    // Scroll-to button
    const scrollBtn = document.createElement('button');
    scrollBtn.className = 'finding-scroll';
    scrollBtn.textContent = '\u2197';
    scrollBtn.title = 'Scroll to element';
    scrollBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      scrollToFinding(finding.id);
    });
    item.appendChild(scrollBtn);

    return item;
  }

  // -------------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------------

  async function scrollToFinding(findingId) {
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        browser.tabs.sendMessage(tab.id, {
          type: 'SCROLL_TO_FINDING',
          findingId,
        });
      }
    } catch { /* ignore */ }
  }

  async function sendToContentScript(message) {
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        browser.tabs.sendMessage(tab.id, message);
      }
    } catch { /* ignore */ }
  }

  // -------------------------------------------------------------------------
  // Event listeners
  // -------------------------------------------------------------------------

  toggleHighlightsEl.addEventListener('change', () => {
    const visible = toggleHighlightsEl.checked;
    browser.storage.sync.set({ highlightsEnabled: visible });
    sendToContentScript({ type: 'TOGGLE_HIGHLIGHTS', visible });
  });

  toggleAiWarningEl.addEventListener('change', () => {
    const visible = toggleAiWarningEl.checked;
    browser.storage.sync.set({ aiWarningEnabled: visible });
    sendToContentScript({ type: 'TOGGLE_AI_WARNING', visible });
  });

  rescanBtn.addEventListener('click', () => {
    sendToContentScript({ type: 'RESCAN' });
    statusLevelEl.textContent = 'Scanning...';
    statusDetailEl.textContent = '';

    // Re-fetch after a short delay
    setTimeout(init, 1500);
  });

  optionsLink.addEventListener('click', (e) => {
    e.preventDefault();
    browser.runtime.openOptionsPage();
  });

  // -------------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------------

  init();
})();
