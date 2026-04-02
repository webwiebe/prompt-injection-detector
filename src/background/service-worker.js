/**
 * Background service worker for the Prompt Injection Detector.
 * Manages per-tab state, badge updates, and message routing.
 */

(() => {
  'use strict';

  const browser = globalThis.browser || globalThis.chrome;

  // Per-tab state
  const tabState = new Map();

  // Badge configuration
  const BADGE_CONFIG = {
    clean: {
      color: '#22c55e',
      text: '',
      iconPrefix: 'badge-green',
    },
    suspicious: {
      color: '#eab308',
      text: '',  // Will be set to finding count
      iconPrefix: 'badge-yellow',
    },
    malicious: {
      color: '#dc2626',
      text: '!',
      iconPrefix: 'badge-red',
    },
  };

  // -------------------------------------------------------------------------
  // Badge management
  // -------------------------------------------------------------------------

  function updateBadge(tabId, threatLevel, findingCount) {
    const config = BADGE_CONFIG[threatLevel] || BADGE_CONFIG.clean;

    const badgeText = threatLevel === 'suspicious'
      ? String(findingCount)
      : config.text;

    browser.action.setBadgeBackgroundColor({ color: config.color, tabId });
    browser.action.setBadgeText({ text: badgeText, tabId });

    // Set colored icon
    browser.action.setIcon({
      path: {
        16: `icons/${config.iconPrefix}.png`,
        32: `icons/${config.iconPrefix}.png`,
      },
      tabId,
    });
  }

  function clearBadge(tabId) {
    browser.action.setBadgeText({ text: '', tabId });
    browser.action.setIcon({
      path: {
        16: 'icons/icon-16.png',
        32: 'icons/icon-32.png',
        48: 'icons/icon-48.png',
        128: 'icons/icon-128.png',
      },
      tabId,
    });
  }

  // -------------------------------------------------------------------------
  // Message handling
  // -------------------------------------------------------------------------

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab?.id;

    switch (message.type) {
      case 'SCAN_RESULTS': {
        if (tabId == null) break;

        const { findings, threatLevel, url, timestamp } = message.data;
        tabState.set(tabId, { findings, threatLevel, url, timestamp });
        updateBadge(tabId, threatLevel, findings.length);
        break;
      }

      case 'GET_TAB_RESULTS': {
        // Called from popup to get results for the active tab
        getActiveTabResults().then(sendResponse);
        return true; // async response
      }
    }
  });

  /**
   * Get scan results for the currently active tab.
   */
  async function getActiveTabResults() {
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tab) return { findings: [], threatLevel: 'clean' };

      const state = tabState.get(tab.id);
      if (state) return state;

      // Try asking the content script directly
      try {
        const response = await browser.tabs.sendMessage(tab.id, { type: 'GET_FINDINGS' });
        return response || { findings: [], threatLevel: 'clean' };
      } catch {
        return { findings: [], threatLevel: 'clean' };
      }
    } catch {
      return { findings: [], threatLevel: 'clean' };
    }
  }

  // -------------------------------------------------------------------------
  // Tab lifecycle
  // -------------------------------------------------------------------------

  browser.tabs.onRemoved.addListener((tabId) => {
    tabState.delete(tabId);
  });

  browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
      // Page is navigating — clear old state
      tabState.delete(tabId);
      clearBadge(tabId);
    }
  });
})();
