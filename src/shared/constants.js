/**
 * Detection rules and constants for the Prompt Injection Detector.
 * This file is the single source of truth for all detection patterns.
 *
 * Loaded as a content script — exposes globals on window.PID.
 */

/* eslint-disable no-unused-vars */

const PID_CONSTANTS = (() => {
  'use strict';

  // ---------------------------------------------------------------------------
  // Invisible Unicode character definitions
  // ---------------------------------------------------------------------------

  const INVISIBLE_CHARS = [
    { name: 'Zero-width space',       codePoint: 0x200B, severity: 'low',      legitimateScripts: ['Arab', 'Deva', 'Beng'] },
    { name: 'ZWNJ',                   codePoint: 0x200C, severity: 'low',      legitimateScripts: ['Arab', 'Deva', 'Beng', 'Pers'] },
    { name: 'ZWJ',                    codePoint: 0x200D, severity: 'low',      legitimateScripts: ['Arab', 'Deva', 'Beng', 'Pers'] },
    { name: 'BOM / ZWNBSP',           codePoint: 0xFEFF, severity: 'medium',   legitimateScripts: [] },
    { name: 'Soft hyphen',            codePoint: 0x00AD, severity: 'low',      legitimateScripts: [] },
    { name: 'LTR mark',               codePoint: 0x200E, severity: 'low',      legitimateScripts: ['Arab', 'Hebr'] },
    { name: 'RTL mark',               codePoint: 0x200F, severity: 'low',      legitimateScripts: ['Arab', 'Hebr'] },
    { name: 'Word joiner',            codePoint: 0x2060, severity: 'low',      legitimateScripts: [] },
    { name: 'Invisible separator',    codePoint: 0x2063, severity: 'medium',   legitimateScripts: [] },
  ];

  // Tag characters U+E0001–U+E007F (supplementary plane — always critical)
  const TAG_CHAR_RANGE = { start: 0xE0001, end: 0xE007F };

  // Variation selectors U+FE00–U+FE0F
  const VARIATION_SELECTOR_RANGE = { start: 0xFE00, end: 0xFE0F };

  // Languages whose scripts legitimately use ZWNJ / ZWJ
  const LEGITIMATE_LANG_PREFIXES = ['ar', 'fa', 'ur', 'hi', 'bn', 'pa', 'gu', 'ta', 'te', 'kn', 'ml', 'si', 'th', 'km', 'my', 'he'];

  // Master regex — matches ALL invisible characters in a single pass.
  // Tag chars are on the supplementary plane → surrogate pair \uDB40[\uDC01-\uDC7F].
  const INVISIBLE_CHAR_REGEX = /[\u200B\u200C\u200D\uFEFF\u00AD\u200E\u200F\u2060\u2063\uFE00-\uFE0F]|\uDB40[\uDC01-\uDC7F]/g;

  // ---------------------------------------------------------------------------
  // CSS-hidden content selectors
  // ---------------------------------------------------------------------------

  // Inline-style selectors to find candidate hidden elements efficiently
  const CSS_HIDDEN_INLINE_SELECTORS = [
    '[style*="display:none"]',
    '[style*="display: none"]',
    '[style*="visibility:hidden"]',
    '[style*="visibility: hidden"]',
    '[style*="opacity:0"]',
    '[style*="opacity: 0"]',
    '[style*="font-size:0"]',
    '[style*="font-size: 0"]',
    '[style*="clip-path"]',
    '[style*="clip:"]',
    '[style*="transform:scale(0"]',
    '[style*="transform: scale(0"]',
  ];

  // Computed style checks to verify an element is truly hidden
  const CSS_HIDDEN_CHECKS = [
    { property: 'display',    value: 'none' },
    { property: 'visibility', value: 'hidden' },
    { property: 'opacity',    value: '0' },
    { property: 'clipPath',   value: 'inset(100%)' },
  ];

  // ---------------------------------------------------------------------------
  // Suspicious HTML patterns
  // ---------------------------------------------------------------------------

  // Keywords that suggest prompt injection when found in hidden contexts
  const INJECTION_KEYWORDS_REGEX = /\b(ignore|previous|instructions?|system|prompt|role|assistant|forget|disregard|override|bypass|jailbreak|pretend|act as|you are|new instructions?|reset|above|context|conversation)\b/i;

  // Minimum text length for hidden content to be considered suspicious
  const MIN_SUSPICIOUS_TEXT_LENGTH = 20;

  // Maximum findings before early exit
  const MAX_FINDINGS = 1000;

  // Chunk size for TreeWalker processing
  const SCAN_CHUNK_SIZE = 500;

  // MutationObserver debounce interval (ms)
  const MUTATION_DEBOUNCE_MS = 300;

  // ---------------------------------------------------------------------------
  // Severity levels (ordered)
  // ---------------------------------------------------------------------------

  const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  // ---------------------------------------------------------------------------
  // Finding types
  // ---------------------------------------------------------------------------

  const FINDING_TYPES = {
    INVISIBLE_UNICODE: 'invisible-unicode',
    CSS_HIDDEN: 'css-hidden',
    HTML_SUSPICIOUS: 'html-suspicious',
  };

  return Object.freeze({
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
    MUTATION_DEBOUNCE_MS,
    SEVERITY_ORDER,
    FINDING_TYPES,
  });
})();
