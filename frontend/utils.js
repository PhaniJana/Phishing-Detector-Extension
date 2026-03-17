/**
 * utils.js - PhishGuard feature extraction helpers
 *
 * Each function returns one of:
 *   -1  => phishing indicator
 *    0  => suspicious / uncertain
 *    1  => legitimate indicator
 *
 * Encoding matches the UCI Phishing Websites Dataset convention so that
 * the feature vector fed to the model is consistent with its training data.
 *
 * These functions are injected before content.js and run in the page context.
 */

'use strict';

function normalizeHostname(hostname) {
  return (hostname || '').toLowerCase().replace(/^www\./, '');
}

function parseUrlSafe(value, base) {
  try {
    return new URL(value, base || window.location.href);
  } catch {
    return null;
  }
}

function isSameOrSubdomain(targetHost, pageHost) {
  const t = normalizeHostname(targetHost);
  const p = normalizeHostname(pageHost);
  return t === p || t.endsWith(`.${p}`);
}

// ───────────────── URL FEATURES ─────────────────

function hasIPAddress(url) {
  const ipv4 = /(\d{1,3}\.){3}\d{1,3}/;
  const hex = /0x[0-9a-fA-F]+/;
  return (ipv4.test(url) || hex.test(url)) ? -1 : 1;
}

function getURLLength(url) {
  if (url.length < 54) return 1;
  if (url.length <= 75) return 0;
  return -1;
}

const SHORTENERS = new Set([
  'bit.ly','goo.gl','tinyurl.com','t.co','is.gd','ow.ly','rb.gy','cutt.ly'
]);

function isShortened(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    return SHORTENERS.has(host) ? -1 : 1;
  } catch {
    return 1;
  }
}

function hasAtSymbol(url) {
  return url.includes('@') ? -1 : 1;
}

function hasDoubleSlashRedirect(url) {
  return url.lastIndexOf('//') > 7 ? -1 : 1;
}

function hasPrefixSuffix(hostname) {
  return hostname.includes('-') ? -1 : 1;
}

function countSubDomains(hostname) {
  const dots = (normalizeHostname(hostname).match(/\./g) || []).length;
  if (dots === 1) return 1;
  if (dots === 2) return 0;
  return -1;
}

function hasHTTPSToken(hostname) {
  return hostname.includes('https') ? -1 : 1;
}

function getNonStandardPort(url) {
  try {
    const port = new URL(url).port;
    if (!port) return 1;
    return (port === "80" || port === "443") ? 1 : -1;
  } catch {
    return 1;
  }
}

function isAbnormalURL(url, hostname) {
  try {
    const u = new URL(url);
    return u.hostname.includes(hostname) ? 1 : -1;
  } catch {
    return -1;
  }
}

// ───────────────── DOM FEATURES ─────────────────

function getRequestURLRatio(doc, hostname) {
  const elements = doc.querySelectorAll('img[src], script[src], video[src], audio[src]');
  if (elements.length === 0) return 1;

  let external = 0;

  elements.forEach(el => {
    const src = el.getAttribute('src');
    const u = parseUrlSafe(src);
    if (u && !isSameOrSubdomain(u.hostname, hostname)) external++;
  });

  const ratio = (external / elements.length) * 100;

  if (ratio < 22) return 1;
  if (ratio <= 61) return 0;
  return -1;
}

function getAnchorURLRatio(doc, hostname) {
  const anchors = doc.querySelectorAll('a');
  if (anchors.length === 0) return 1;

  let suspicious = 0;

  anchors.forEach(a => {
    const href = (a.getAttribute('href') || '').toLowerCase();

    if (
      href === '' ||
      href === '#' ||
      href.startsWith('javascript')
    ) {
      suspicious++;
    } else {
      const u = parseUrlSafe(href);
      if (u && !isSameOrSubdomain(u.hostname, hostname)) suspicious++;
    }
  });

  const ratio = (suspicious / anchors.length) * 100;

  if (ratio < 31) return 1;
  if (ratio <= 67) return 0;
  return -1;
}

function getLinksInTagsRatio(doc, hostname) {
  const tags = doc.querySelectorAll('meta, script[src], link[href]');
  if (tags.length === 0) return 1;

  let external = 0;

  tags.forEach(tag => {
    const val = tag.getAttribute('src') || tag.getAttribute('href');
    const u = parseUrlSafe(val);
    if (u && !isSameOrSubdomain(u.hostname, hostname)) external++;
  });

  const ratio = (external / tags.length) * 100;

  if (ratio < 17) return 1;
  if (ratio <= 81) return 0;
  return -1;
}

function getSFH(doc, hostname) {
  const forms = doc.querySelectorAll('form');
  if (forms.length === 0) return 1;

  let suspicious = false;

  for (const form of forms) {
    const action = (form.getAttribute('action') || '').toLowerCase();

    if (action === '' || action === 'about:blank') return -1;

    const u = parseUrlSafe(action);
    if (u && !isSameOrSubdomain(u.hostname, hostname)) {
      suspicious = true;
    }
  }

  return suspicious ? 0 : 1;
}

function getFaviconFeature(doc, hostname) {
  const icon = doc.querySelector('link[rel~="icon"]');
  if (!icon) return 1;

  const href = icon.getAttribute('href');
  const u = parseUrlSafe(href);

  return (u && !isSameOrSubdomain(u.hostname, hostname)) ? -1 : 1;
}

function hasEmailSubmit(doc) {
  return doc.querySelector('form[action^="mailto"]') ? -1 : 1;
}

function hasOnMouseover(doc) {
  const scripts = Array.from(doc.querySelectorAll('script'))
    .map(s => s.textContent).join(' ');

  return scripts.includes('window.status') ? -1 : 1;
}

function isRightClickDisabled(doc) {
  const html = doc.body.innerHTML;
  return html.includes('contextmenu') ? -1 : 1;
}

function hasPopupWindow(doc) {
  const scripts = Array.from(doc.querySelectorAll('script'))
    .map(s => s.textContent).join(' ');

  const inputs = doc.querySelectorAll('input');

  return (scripts.includes('window.open') && inputs.length > 0) ? -1 : 1;
}

function hasIframe(doc) {
  const iframes = doc.querySelectorAll('iframe');
  return iframes.length > 0 ? -1 : 1;
}

// ───────────────── NAVIGATION ─────────────────

function getRedirectCount() {
  try {
    const nav = performance.getEntriesByType('navigation')[0];
    const count = nav ? nav.redirectCount : 0;

    if (count <= 1) return 1;
    if (count < 4) return 0;
    return -1;
  } catch {
    return 1;
  }
}