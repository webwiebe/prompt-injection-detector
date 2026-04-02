/**
 * Core detection engine for the Prompt Injection Detector.
 * Implements three scanning strategies:
 *   1. Invisible Unicode character detection
 *   2. CSS-hidden content detection
 *   3. Suspicious HTML pattern detection
 *
 * Loaded after constants.js and threat-model.js.
 */

/* eslint-disable no-unused-vars */

const PID_SCANNER = (() => {
  'use strict';

  const {
    INVISIBLE_CHARS,
    TAG_CHAR_RANGE,
    VARIATION_SELECTOR_RANGE,
    LEGITIMATE_LANG_PREFIXES,
    INVISIBLE_CHAR_REGEX,
    CSS_HIDDEN_INLINE_SELECTORS,
    CSS_HIDDEN_CHECKS,
    INJECTION_KEYWORDS_REGEX,
    MIN_SUSPICIOUS_TEXT_LENGTH,
    MAX_FINDINGS,
    SCAN_CHUNK_SIZE,
    FINDING_TYPES,
  } = PID_CONSTANTS;

  const { ThreatFinding, getXPath } = PID_THREAT;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Check if an element (or any ancestor) declares a language that legitimately
   * uses zero-width joiners.
   */
  function hasLegitimateScriptLang(element) {
    let el = element;
    while (el && el.nodeType === Node.ELEMENT_NODE) {
      const lang = el.getAttribute('lang') || el.getAttribute('xml:lang');
      if (lang) {
        const prefix = lang.split('-')[0].toLowerCase();
        return LEGITIMATE_LANG_PREFIXES.includes(prefix);
      }
      el = el.parentElement;
    }
    return false;
  }

  /**
   * Get the code point at a position in a string, handling surrogate pairs.
   */
  function codePointAtPos(str, i) {
    const code = str.charCodeAt(i);
    // High surrogate
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
      const low = str.charCodeAt(i + 1);
      if (low >= 0xDC00 && low <= 0xDFFF) {
        return (code - 0xD800) * 0x400 + (low - 0xDC00) + 0x10000;
      }
    }
    return code;
  }

  /**
   * Decode Unicode tag characters to their visible equivalents.
   * Tag chars U+E0001–U+E007F map to ASCII by subtracting 0xE0000.
   */
  function decodeTagCharacters(text) {
    let decoded = '';
    for (let i = 0; i < text.length; i++) {
      const cp = codePointAtPos(text, i);
      if (cp >= TAG_CHAR_RANGE.start && cp <= TAG_CHAR_RANGE.end) {
        decoded += String.fromCharCode(cp - 0xE0000);
      }
      // Skip low surrogate of a pair
      if (cp > 0xFFFF) i++;
    }
    return decoded;
  }

  /**
   * Classify a matched invisible character code point.
   */
  function classifyChar(codePoint, element) {
    // Tag characters — always critical
    if (codePoint >= TAG_CHAR_RANGE.start && codePoint <= TAG_CHAR_RANGE.end) {
      return { severity: 'critical', name: 'Unicode tag character' };
    }

    // Variation selectors
    if (codePoint >= VARIATION_SELECTOR_RANGE.start && codePoint <= VARIATION_SELECTOR_RANGE.end) {
      return { severity: 'low', name: 'Variation selector' };
    }

    // Known single-codepoint characters
    const def = INVISIBLE_CHARS.find(c => c.codePoint === codePoint);
    if (def) {
      let severity = def.severity;
      // Downgrade if the character is legitimate for the page's script
      if (def.legitimateScripts.length > 0 && element && hasLegitimateScriptLang(element)) {
        severity = 'info';
      }
      return { severity, name: def.name };
    }

    return { severity: 'low', name: `Invisible char U+${codePoint.toString(16).toUpperCase()}` };
  }

  /**
   * Extract a short snippet around a match position for context.
   */
  function snippetAround(text, index, radius = 30) {
    const start = Math.max(0, index - radius);
    const end = Math.min(text.length, index + radius);
    let snippet = text.slice(start, end).replace(/[\n\r\t]+/g, ' ');
    if (start > 0) snippet = '...' + snippet;
    if (end < text.length) snippet += '...';
    return snippet;
  }

  // -------------------------------------------------------------------------
  // 1. Invisible Unicode character scanning
  // -------------------------------------------------------------------------

  /**
   * Scan a single text node for invisible Unicode characters.
   * @returns {ThreatFinding[]}
   */
  function scanTextNode(textNode) {
    const text = textNode.textContent;
    if (!text) return [];

    const findings = [];
    const regex = new RegExp(INVISIBLE_CHAR_REGEX.source, 'g');
    let match;

    // Track tag character sequences for decoding
    let tagSequenceStart = -1;
    let tagSequenceText = '';

    while ((match = regex.exec(text)) !== null) {
      const matchStr = match[0];
      const pos = match.index;
      const cp = codePointAtPos(text, pos);
      const { severity, name } = classifyChar(cp, textNode.parentElement);

      // Accumulate tag character sequences
      const isTag = cp >= TAG_CHAR_RANGE.start && cp <= TAG_CHAR_RANGE.end;
      if (isTag) {
        if (tagSequenceStart === -1) tagSequenceStart = pos;
        tagSequenceText += matchStr;
      }

      // Only create individual findings for non-tag chars or when
      // we'll batch tag chars below
      if (!isTag) {
        // Flush any accumulated tag sequence
        if (tagSequenceText) {
          findings.push(createTagFinding(textNode, tagSequenceStart, tagSequenceText, text));
          tagSequenceStart = -1;
          tagSequenceText = '';
        }

        findings.push(new ThreatFinding({
          type: FINDING_TYPES.INVISIBLE_UNICODE,
          severity,
          charCode: cp,
          charName: name,
          position: { xpath: getXPath(textNode), textOffset: pos },
          textSnippet: snippetAround(text, pos),
          description: `${name} (U+${cp.toString(16).toUpperCase().padStart(4, '0')}) detected`,
          element: textNode.parentElement,
        }));
      }
    }

    // Flush trailing tag sequence
    if (tagSequenceText) {
      findings.push(createTagFinding(textNode, tagSequenceStart, tagSequenceText, text));
    }

    return findings;
  }

  /**
   * Create a single finding for a contiguous sequence of tag characters.
   */
  function createTagFinding(textNode, startPos, tagText, fullText) {
    const decoded = decodeTagCharacters(tagText);
    return new ThreatFinding({
      type: FINDING_TYPES.INVISIBLE_UNICODE,
      severity: 'critical',
      charCode: 0xE0000,
      charName: 'Unicode tag character sequence',
      position: { xpath: getXPath(textNode), textOffset: startPos },
      textSnippet: snippetAround(fullText, startPos),
      description: `Hidden message encoded in Unicode tag characters: "${decoded}"`,
      decodedText: decoded,
      element: textNode.parentElement,
    });
  }

  // -------------------------------------------------------------------------
  // 2. CSS-hidden content scanning
  // -------------------------------------------------------------------------

  /**
   * Check if an element's computed style makes it invisible.
   */
  function isComputedHidden(el) {
    let style;
    try {
      style = window.getComputedStyle(el);
    } catch {
      return false;
    }

    if (style.display === 'none') return 'display:none';
    if (style.visibility === 'hidden') return 'visibility:hidden';
    if (style.opacity === '0') return 'opacity:0';
    if (parseFloat(style.fontSize) === 0) return 'font-size:0';

    // Off-screen positioning
    const rect = el.getBoundingClientRect();
    if (rect.right < -9000 || rect.left > 9000 || rect.bottom < -9000 || rect.top > 9000) {
      return 'off-screen positioning';
    }

    // Zero dimensions with overflow hidden
    if ((rect.width === 0 || rect.height === 0) && style.overflow === 'hidden') {
      return 'zero-size with overflow:hidden';
    }

    // Clip path
    if (style.clipPath === 'inset(100%)') return 'clip-path:inset(100%)';

    // Transform scale(0)
    const transform = style.transform;
    if (transform && /matrix\(0,\s*0,\s*0,\s*0/.test(transform)) return 'transform:scale(0)';

    // Color matching background (simplified — compare text color to bg color)
    const color = style.color;
    const bgColor = style.backgroundColor;
    if (color && bgColor && color === bgColor && bgColor !== 'rgba(0, 0, 0, 0)') {
      return 'text color matches background';
    }

    return false;
  }

  /**
   * Scan the page for CSS-hidden elements containing suspicious text.
   * @returns {ThreatFinding[]}
   */
  function scanCSSHidden() {
    const findings = [];
    const seen = new Set();

    // Query by inline style hints
    const selector = CSS_HIDDEN_INLINE_SELECTORS.join(', ');
    let candidates;
    try {
      candidates = document.querySelectorAll(selector);
    } catch {
      candidates = [];
    }

    // Also check common hiding classes
    const additionalSelectors = [
      '.hidden', '.sr-only', '.visually-hidden', '.screen-reader-text',
      '[hidden]', '[aria-hidden="true"]',
    ];
    try {
      const extra = document.querySelectorAll(additionalSelectors.join(', '));
      candidates = [...candidates, ...extra];
    } catch { /* ignore */ }

    for (const el of candidates) {
      if (seen.has(el)) continue;
      seen.add(el);
      if (findings.length >= MAX_FINDINGS) break;

      const text = (el.textContent || '').trim();
      if (text.length < MIN_SUSPICIOUS_TEXT_LENGTH) continue;

      const hiddenBy = isComputedHidden(el);
      if (!hiddenBy) continue;

      // Check for injection keywords
      if (!INJECTION_KEYWORDS_REGEX.test(text)) continue;

      findings.push(new ThreatFinding({
        type: FINDING_TYPES.CSS_HIDDEN,
        severity: 'high',
        position: { xpath: getXPath(el) },
        textSnippet: text.slice(0, 200) + (text.length > 200 ? '...' : ''),
        description: `Hidden element (${hiddenBy}) contains suspicious text`,
        element: el,
      }));
    }

    return findings;
  }

  // -------------------------------------------------------------------------
  // 3. Suspicious HTML pattern scanning
  // -------------------------------------------------------------------------

  /**
   * Scan HTML comments for injection keywords.
   * @returns {ThreatFinding[]}
   */
  function scanHTMLComments() {
    const findings = [];
    const walker = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_COMMENT,
    );

    let node;
    while ((node = walker.nextNode()) && findings.length < MAX_FINDINGS) {
      const text = (node.textContent || '').trim();
      if (text.length < MIN_SUSPICIOUS_TEXT_LENGTH) continue;
      if (!INJECTION_KEYWORDS_REGEX.test(text)) continue;

      findings.push(new ThreatFinding({
        type: FINDING_TYPES.HTML_SUSPICIOUS,
        severity: 'high',
        position: { xpath: getXPath(node.parentNode) },
        textSnippet: text.slice(0, 200) + (text.length > 200 ? '...' : ''),
        description: 'HTML comment contains suspicious injection keywords',
        element: node.parentNode,
      }));
    }

    return findings;
  }

  /**
   * Scan aria-hidden elements for substantial text content.
   * @returns {ThreatFinding[]}
   */
  function scanAriaHidden() {
    const findings = [];
    let elements;
    try {
      elements = document.querySelectorAll('[aria-hidden="true"]');
    } catch {
      return findings;
    }

    for (const el of elements) {
      if (findings.length >= MAX_FINDINGS) break;
      const text = (el.textContent || '').trim();
      if (text.length < MIN_SUSPICIOUS_TEXT_LENGTH) continue;
      if (!INJECTION_KEYWORDS_REGEX.test(text)) continue;

      findings.push(new ThreatFinding({
        type: FINDING_TYPES.HTML_SUSPICIOUS,
        severity: 'medium',
        position: { xpath: getXPath(el) },
        textSnippet: text.slice(0, 200) + (text.length > 200 ? '...' : ''),
        description: 'aria-hidden element contains suspicious text',
        element: el,
      }));
    }

    return findings;
  }

  /**
   * Scan data-* attributes for injection keywords.
   * @returns {ThreatFinding[]}
   */
  function scanDataAttributes() {
    const findings = [];
    // Only check elements that have data attributes — use a targeted approach
    const allWithData = document.querySelectorAll('[data-prompt], [data-instruction], [data-system], [data-role], [data-message]');

    for (const el of allWithData) {
      if (findings.length >= MAX_FINDINGS) break;
      for (const attr of el.attributes) {
        if (!attr.name.startsWith('data-')) continue;
        const val = attr.value.trim();
        if (val.length < MIN_SUSPICIOUS_TEXT_LENGTH) continue;
        if (!INJECTION_KEYWORDS_REGEX.test(val)) continue;

        findings.push(new ThreatFinding({
          type: FINDING_TYPES.HTML_SUSPICIOUS,
          severity: 'medium',
          position: { xpath: getXPath(el) },
          textSnippet: val.slice(0, 200) + (val.length > 200 ? '...' : ''),
          description: `data-* attribute "${attr.name}" contains suspicious text`,
          element: el,
        }));
      }
    }

    return findings;
  }

  /**
   * Scan <noscript> elements for suspicious content.
   * @returns {ThreatFinding[]}
   */
  function scanNoscript() {
    const findings = [];
    const elements = document.querySelectorAll('noscript');

    for (const el of elements) {
      if (findings.length >= MAX_FINDINGS) break;
      const text = (el.textContent || '').trim();
      if (text.length < MIN_SUSPICIOUS_TEXT_LENGTH) continue;
      if (!INJECTION_KEYWORDS_REGEX.test(text)) continue;

      findings.push(new ThreatFinding({
        type: FINDING_TYPES.HTML_SUSPICIOUS,
        severity: 'medium',
        position: { xpath: getXPath(el) },
        textSnippet: text.slice(0, 200) + (text.length > 200 ? '...' : ''),
        description: '<noscript> element contains suspicious text',
        element: el,
      }));
    }

    return findings;
  }

  // -------------------------------------------------------------------------
  // Orchestration
  // -------------------------------------------------------------------------

  /**
   * Scan all text nodes for invisible characters using chunked TreeWalker.
   * Yields control back to the browser between chunks to avoid jank.
   *
   * @returns {Promise<ThreatFinding[]>}
   */
  function scanInvisibleChars() {
    return new Promise((resolve) => {
      const findings = [];
      const walker = document.createTreeWalker(
        document.body || document.documentElement,
        NodeFilter.SHOW_TEXT,
      );

      let count = 0;

      function processChunk() {
        let node;
        let chunkCount = 0;

        while ((node = walker.nextNode()) && chunkCount < SCAN_CHUNK_SIZE) {
          if (findings.length >= MAX_FINDINGS) {
            resolve(findings);
            return;
          }

          const nodeFindings = scanTextNode(node);
          if (nodeFindings.length > 0) {
            findings.push(...nodeFindings);
          }
          chunkCount++;
          count++;
        }

        if (node) {
          // More nodes to process — yield and continue
          if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(processChunk);
          } else {
            setTimeout(processChunk, 0);
          }
        } else {
          resolve(findings);
        }
      }

      processChunk();
    });
  }

  /**
   * Run a full page scan (all three detection strategies).
   *
   * @returns {Promise<{ findings: ThreatFinding[], threatLevel: string }>}
   */
  async function scanPage() {
    // Run invisible char scan (async/chunked)
    const unicodeFindings = await scanInvisibleChars();

    // Run synchronous scans
    const cssFindings = scanCSSHidden();
    const commentFindings = scanHTMLComments();
    const ariaFindings = scanAriaHidden();
    const dataFindings = scanDataAttributes();
    const noscriptFindings = scanNoscript();

    const findings = [
      ...unicodeFindings,
      ...cssFindings,
      ...commentFindings,
      ...ariaFindings,
      ...dataFindings,
      ...noscriptFindings,
    ].slice(0, MAX_FINDINGS);

    const threatLevel = PID_THREAT.computePageThreatLevel(findings);

    return { findings, threatLevel };
  }

  /**
   * Scan a single DOM node (for incremental MutationObserver updates).
   * @param {Node} node
   * @returns {ThreatFinding[]}
   */
  function scanNode(node) {
    const findings = [];

    if (node.nodeType === Node.TEXT_NODE) {
      findings.push(...scanTextNode(node));
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      // Scan text descendants
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
      let textNode;
      while ((textNode = walker.nextNode())) {
        findings.push(...scanTextNode(textNode));
        if (findings.length >= MAX_FINDINGS) break;
      }

      // Check if this element itself is hidden with suspicious content
      const text = (node.textContent || '').trim();
      if (text.length >= MIN_SUSPICIOUS_TEXT_LENGTH) {
        const hiddenBy = isComputedHidden(node);
        if (hiddenBy && INJECTION_KEYWORDS_REGEX.test(text)) {
          findings.push(new ThreatFinding({
            type: FINDING_TYPES.CSS_HIDDEN,
            severity: 'high',
            position: { xpath: getXPath(node) },
            textSnippet: text.slice(0, 200),
            description: `Hidden element (${hiddenBy}) contains suspicious text`,
            element: node,
          }));
        }
      }
    } else if (node.nodeType === Node.COMMENT_NODE) {
      const text = (node.textContent || '').trim();
      if (text.length >= MIN_SUSPICIOUS_TEXT_LENGTH && INJECTION_KEYWORDS_REGEX.test(text)) {
        findings.push(new ThreatFinding({
          type: FINDING_TYPES.HTML_SUSPICIOUS,
          severity: 'high',
          position: { xpath: getXPath(node.parentNode) },
          textSnippet: text.slice(0, 200),
          description: 'HTML comment contains suspicious injection keywords',
          element: node.parentNode,
        }));
      }
    }

    return findings;
  }

  return Object.freeze({
    scanPage,
    scanNode,
    scanTextNode,
    decodeTagCharacters,
    scanCSSHidden,
    scanHTMLComments,
    scanAriaHidden,
    scanDataAttributes,
    scanNoscript,
  });
})();
