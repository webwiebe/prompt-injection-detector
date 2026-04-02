/**
 * ThreatFinding data structure and page-level threat scoring.
 * Loaded as a content script after constants.js — uses PID_CONSTANTS global.
 */

/* eslint-disable no-unused-vars */

const PID_THREAT = (() => {
  'use strict';

  const { SEVERITY_ORDER } = PID_CONSTANTS;

  /** Unique ID counter for findings */
  let _nextId = 1;

  /**
   * Represents a single detected threat finding.
   */
  class ThreatFinding {
    constructor({ type, severity, charCode = null, charName = null, position = null, textSnippet = '', description = '', decodedText = null, element = null }) {
      this.id = _nextId++;
      this.type = type;
      this.severity = severity;
      this.charCode = charCode;
      this.charName = charName;
      this.position = position;   // { xpath, textOffset }
      this.textSnippet = textSnippet;
      this.description = description;
      this.decodedText = decodedText;
      this.element = element;     // DOM reference — NOT serialized
    }

    /**
     * Serialize for message passing (strips DOM reference).
     */
    serialize() {
      return {
        id: this.id,
        type: this.type,
        severity: this.severity,
        charCode: this.charCode,
        charName: this.charName,
        position: this.position,
        textSnippet: this.textSnippet,
        description: this.description,
        decodedText: this.decodedText,
      };
    }
  }

  /**
   * Compute an XPath for a DOM node (best-effort, for relocating elements).
   */
  function getXPath(node) {
    if (!node) return '';
    if (node.nodeType === Node.TEXT_NODE) {
      return getXPath(node.parentNode) + '/text()';
    }
    if (node === document.body) return '/html/body';
    if (node === document.documentElement) return '/html';

    const parent = node.parentNode;
    if (!parent) return '';

    const siblings = Array.from(parent.children).filter(c => c.tagName === node.tagName);
    const index = siblings.indexOf(node) + 1;
    const tag = node.tagName.toLowerCase();
    const suffix = siblings.length > 1 ? `[${index}]` : '';

    return getXPath(parent) + '/' + tag + suffix;
  }

  /**
   * Compute the overall threat level for a page based on findings.
   *
   * @param {ThreatFinding[]} findings
   * @returns {'clean' | 'suspicious' | 'malicious'}
   */
  function computePageThreatLevel(findings) {
    if (!findings || findings.length === 0) return 'clean';

    const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }

    // Any critical → malicious
    if (counts.critical > 0) return 'malicious';

    // >=3 high OR (any high + >=5 medium) → malicious
    if (counts.high >= 3) return 'malicious';
    if (counts.high > 0 && counts.medium >= 5) return 'malicious';

    // Any high OR >=5 medium → suspicious
    if (counts.high > 0) return 'suspicious';
    if (counts.medium >= 5) return 'suspicious';

    // >=10 low → suspicious (concentration heuristic)
    if (counts.low >= 10) return 'suspicious';

    // Remaining low/info findings → clean
    return 'clean';
  }

  /**
   * Serialize an array of findings for message passing.
   */
  function serializeFindings(findings) {
    return findings.map(f => f.serialize());
  }

  return Object.freeze({
    ThreatFinding,
    getXPath,
    computePageThreatLevel,
    serializeFindings,
  });
})();
