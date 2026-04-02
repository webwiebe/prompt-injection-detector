/**
 * Options page — loads and saves user preferences to chrome.storage.sync.
 */

(() => {
  'use strict';

  const browser = globalThis.browser || globalThis.chrome;

  const DEFAULTS = {
    sensitivity: 'medium',
    highlightsEnabled: true,
    aiWarningEnabled: false,
    ignoreLegitimateJoiners: true,
    allowlistedDomains: [],
  };

  // DOM refs
  const sensitivityRadios = document.querySelectorAll('input[name="sensitivity"]');
  const highlightsEl = document.getElementById('highlights-enabled');
  const aiWarningEl = document.getElementById('ai-warning-enabled');
  const joinersEl = document.getElementById('ignore-legitimate-joiners');
  const domainsEl = document.getElementById('allowlisted-domains');
  const saveBtn = document.getElementById('save-btn');
  const saveStatus = document.getElementById('save-status');

  /**
   * Load saved options into the form.
   */
  async function load() {
    try {
      const opts = await browser.storage.sync.get(DEFAULTS);

      // Sensitivity
      for (const radio of sensitivityRadios) {
        radio.checked = radio.value === opts.sensitivity;
      }

      highlightsEl.checked = opts.highlightsEnabled;
      aiWarningEl.checked = opts.aiWarningEnabled;
      joinersEl.checked = opts.ignoreLegitimateJoiners;
      domainsEl.value = (opts.allowlistedDomains || []).join('\n');
    } catch {
      // Defaults already set in HTML
    }
  }

  /**
   * Save current form state.
   */
  async function save() {
    const sensitivity = Array.from(sensitivityRadios).find(r => r.checked)?.value || 'medium';

    const allowlistedDomains = domainsEl.value
      .split('\n')
      .map(d => d.trim().toLowerCase())
      .filter(d => d.length > 0);

    const opts = {
      sensitivity,
      highlightsEnabled: highlightsEl.checked,
      aiWarningEnabled: aiWarningEl.checked,
      ignoreLegitimateJoiners: joinersEl.checked,
      allowlistedDomains,
    };

    try {
      await browser.storage.sync.set(opts);
      saveStatus.textContent = 'Saved';
      setTimeout(() => { saveStatus.textContent = ''; }, 2000);
    } catch (err) {
      saveStatus.textContent = 'Error saving';
      saveStatus.style.color = '#dc2626';
    }
  }

  saveBtn.addEventListener('click', save);

  load();
})();
