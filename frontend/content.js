/**
 * content.js - PhishGuard content script
 *
 * Runs at document_idle on every page after utils.js is injected.
 * Responsibilities:
 *   1. Extract URL and DOM features using helpers from utils.js
 *   2. Send features to background.js for ML prediction
 *   3. If a page is flagged as phishing, show a warning overlay
 *   4. Allow continuing in a protected safe mode that blocks risky actions
 */

(async function () {
  'use strict';

  const LOG = '[PhishGuard]';
  const SCAN_BADGE_ID = 'phishguard-scan-badge';
  const SCAN_STYLE_ID = 'phishguard-scan-style';
  const OVERLAY_ID = 'phishguard-warning-overlay';
  const STYLE_TAG_ID = 'phishguard-styles';
  const SAFE_MODE_STYLE_ID = 'phishguard-safe-mode-style';
  const SAFE_MODE_BANNER_ID = 'phishguard-safe-mode-banner';
  const SAFE_MODE_CLASS = 'phishguard-safe-mode';

  let safeModeEnabled = false;

  function getHostname() {
    try {
      return new URL(window.location.href).hostname.toLowerCase();
    } catch (e) {
      return window.location.hostname.toLowerCase();
    }
  }

  function sendMessageAsync(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  function ensureScanBadge() {
    if (!document.getElementById(SCAN_STYLE_ID)) {
      const style = document.createElement('style');
      style.id = SCAN_STYLE_ID;
      style.textContent = `
        #${SCAN_BADGE_ID} {
          position: fixed;
          top: 12px;
          right: 12px;
          z-index: 2147483646;
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 7px 10px;
          border-radius: 999px;
          background: rgba(17, 24, 39, 0.92);
          color: #ffffff;
          font: 600 12px/1 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          box-shadow: 0 8px 20px rgba(0, 0, 0, 0.35);
          transition: opacity .2s ease, transform .2s ease, background .2s ease;
        }
        #${SCAN_BADGE_ID}.pg-hidden {
          opacity: 0;
          transform: translateY(-6px);
          pointer-events: none;
        }
        #${SCAN_BADGE_ID} .pg-spinner {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          border: 2px solid rgba(255, 255, 255, 0.35);
          border-top-color: #ffffff;
          animation: pg-spin .8s linear infinite;
          flex-shrink: 0;
        }
        #${SCAN_BADGE_ID}.pg-safe {
          background: rgba(5, 150, 105, 0.92);
        }
        #${SCAN_BADGE_ID}.pg-danger {
          background: rgba(185, 28, 28, 0.94);
        }
        #${SCAN_BADGE_ID}.pg-safe .pg-spinner,
        #${SCAN_BADGE_ID}.pg-danger .pg-spinner {
          display: none;
        }
        @keyframes pg-spin {
          to { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }

    let badge = document.getElementById(SCAN_BADGE_ID);
    if (!badge) {
      badge = document.createElement('div');
      badge.id = SCAN_BADGE_ID;
      badge.innerHTML = '<span class="pg-spinner" aria-hidden="true"></span><span class="pg-text">Scanning...</span>';
      (document.body || document.documentElement).appendChild(badge);
    }
    return badge;
  }

  function updateScanBadge(state, detail) {
    const badge = ensureScanBadge();
    const text = badge.querySelector('.pg-text');

    badge.classList.remove('pg-safe', 'pg-danger', 'pg-hidden');

    if (state === 'scanning') {
      text.textContent = 'Scanning...';
      return;
    }

    if (state === 'safe') {
      text.textContent = detail || 'Safe';
      badge.classList.add('pg-safe');
      setTimeout(() => badge.classList.add('pg-hidden'), 1800);
      return;
    }

    if (state === 'phishing') {
      text.textContent = detail || 'Phishing detected';
      badge.classList.add('pg-danger');
      return;
    }

    text.textContent = detail || 'Scan failed';
    badge.classList.add('pg-danger');
    setTimeout(() => badge.classList.add('pg-hidden'), 2500);
  }

  function validateFeatureEncoding(features) {
    const invalidEntries = Object.entries(features).filter(([, value]) => ![-1, 0, 1].includes(value));

    if (invalidEntries.length > 0) {
      console.error(`${LOG} Invalid feature encodings detected:`, invalidEntries);
      throw new Error(`Invalid feature encoding for: ${invalidEntries.map(([name]) => name).join(', ')}`);
    }
  }

  function extractFeatures() {
    const url = window.location.href;
    const hostname = getHostname();
    const doc = document;

    const features = {
      having_IPhaving_IP_Address: hasIPAddress(url),
      URLURL_Length: getURLLength(url),
      Shortining_Service: isShortened(url),
      having_At_Symbol: hasAtSymbol(url),
      double_slash_redirecting: hasDoubleSlashRedirect(url),
      Prefix_Suffix: hasPrefixSuffix(hostname),
      having_Sub_Domain: countSubDomains(hostname),
      HTTPS_token: hasHTTPSToken(hostname),
      Favicon: getFaviconFeature(doc, hostname),
      port: getNonStandardPort(url),
      Abnormal_URL: isAbnormalURL(url, hostname),
      Request_URL: getRequestURLRatio(doc, hostname),
      URL_of_Anchor: getAnchorURLRatio(doc, hostname),
      Links_in_tags: getLinksInTagsRatio(doc, hostname),
      SFH: getSFH(doc, hostname),
      Submitting_to_email: hasEmailSubmit(doc),
      on_mouseover: hasOnMouseover(doc),
      RightClick: isRightClickDisabled(doc),
      popUpWidnow: hasPopupWindow(doc),
      Iframe: hasIframe(doc),
      Redirect: getRedirectCount(),
    };

    validateFeatureEncoding(features);
    console.log(`${LOG} Extracted ${Object.keys(features).length} features:`, features);
    return features;
  }

  function isExtensionUi(target) {
    return !!target.closest(`#${OVERLAY_ID}, #${SAFE_MODE_BANNER_ID}, #${SCAN_BADGE_ID}`);
  }

  function getBlockedInteractionTarget(target) {
    if (!target || isExtensionUi(target)) return null;

    return target.closest([
      'a[href]',
      'area[href]',
      'form',
      'input:not([type="hidden"])',
      'textarea',
      'select',
      'button[type="submit"]',
      'input[type="submit"]',
      '[contenteditable=""]',
      '[contenteditable="true"]',
    ].join(', '));
  }

  function ensureSafeModeStyle() {
    if (document.getElementById(SAFE_MODE_STYLE_ID)) return;

    const style = document.createElement('style');
    style.id = SAFE_MODE_STYLE_ID;
    style.textContent = `
      html.${SAFE_MODE_CLASS} a[href],
      html.${SAFE_MODE_CLASS} area[href] {
        pointer-events: none !important;
        cursor: not-allowed !important;
        opacity: 0.6 !important;
        text-decoration: line-through !important;
      }
      html.${SAFE_MODE_CLASS} input:not([type="hidden"]),
      html.${SAFE_MODE_CLASS} textarea,
      html.${SAFE_MODE_CLASS} select,
      html.${SAFE_MODE_CLASS} button[type="submit"],
      html.${SAFE_MODE_CLASS} input[type="submit"],
      html.${SAFE_MODE_CLASS} [contenteditable=""],
      html.${SAFE_MODE_CLASS} [contenteditable="true"] {
        pointer-events: none !important;
        caret-color: transparent !important;
        user-select: none !important;
        opacity: 0.55 !important;
        background: #f3f4f6 !important;
        color: #6b7280 !important;
      }
      #${SAFE_MODE_BANNER_ID} {
        position: fixed;
        left: 16px;
        right: 16px;
        bottom: 16px;
        z-index: 2147483646;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 14px 18px;
        border-radius: 16px;
        background: rgba(127, 29, 29, 0.96);
        color: #fff7ed;
        box-shadow: 0 18px 40px rgba(0, 0, 0, 0.35);
        font: 600 14px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      #${SAFE_MODE_BANNER_ID} .pg-safe-copy {
        min-width: 0;
      }
      #${SAFE_MODE_BANNER_ID} .pg-safe-title {
        display: block;
        margin-bottom: 2px;
        font-size: 14px;
      }
      #${SAFE_MODE_BANNER_ID} .pg-safe-note {
        display: block;
        font-size: 12px;
        font-weight: 500;
        color: #fecaca;
      }
      #${SAFE_MODE_BANNER_ID} button {
        border: none;
        border-radius: 999px;
        padding: 10px 16px;
        background: #fff7ed;
        color: #7f1d1d;
        font: inherit;
        font-weight: 700;
        cursor: pointer;
        flex-shrink: 0;
      }
      @media (max-width: 640px) {
        #${SAFE_MODE_BANNER_ID} {
          flex-direction: column;
          align-items: stretch;
        }
        #${SAFE_MODE_BANNER_ID} button {
          width: 100%;
        }
      }
    `;
    document.head.appendChild(style);
  }

  function ensureSafeModeBanner() {
    let banner = document.getElementById(SAFE_MODE_BANNER_ID);
    if (banner) return banner;

    banner = document.createElement('div');
    banner.id = SAFE_MODE_BANNER_ID;
    banner.innerHTML = `
      <div class="pg-safe-copy">
        <span class="pg-safe-title">Safe mode is on for this phishing page.</span>
        <span class="pg-safe-note">Links, form fields, and submissions are blocked to protect your data.</span>
      </div>
      <button type="button" id="pg-safe-back-btn">Leave This Page</button>
    `;

    banner.querySelector('#pg-safe-back-btn').addEventListener('click', () => {
      window.history.back();
    });

    document.body.appendChild(banner);
    return banner;
  }

  function blockSafeModeInteraction(event) {
    if (!safeModeEnabled) return;

    const blockedTarget = getBlockedInteractionTarget(event.target);
    if (!blockedTarget) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    if (typeof blockedTarget.blur === 'function') {
      blockedTarget.blur();
    }

    updateScanBadge('phishing', 'Safe mode: interaction blocked');
    console.warn(`${LOG} Blocked interaction with protected element:`, blockedTarget);
  }

  function blockSafeModeFocus(event) {
    if (!safeModeEnabled) return;

    const blockedTarget = getBlockedInteractionTarget(event.target);
    if (!blockedTarget) return;

    if (typeof blockedTarget.blur === 'function') {
      blockedTarget.blur();
    }
  }

  function enableSafeMode() {
    if (safeModeEnabled) return;

    safeModeEnabled = true;
    ensureSafeModeStyle();
    document.documentElement.classList.add(SAFE_MODE_CLASS);
    ensureSafeModeBanner();

    document.addEventListener('click', blockSafeModeInteraction, true);
    document.addEventListener('submit', blockSafeModeInteraction, true);
    document.addEventListener('focusin', blockSafeModeFocus, true);

    console.warn(`${LOG} Safe mode enabled. Inputs, links, and submissions are blocked.`);
  }

  function injectWarningOverlay(probability) {
    if (document.getElementById(OVERLAY_ID)) return;

    const confidenceText = (probability != null && probability > 0)
      ? `${(probability * 100).toFixed(1)}% confidence`
      : 'High confidence';

    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    Object.assign(overlay.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '100vw',
      height: '100vh',
      background: 'rgba(0, 0, 0, 0.88)',
      zIndex: '2147483647',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      boxSizing: 'border-box',
    });

    overlay.innerHTML = `
      <div id="pg-box">
        <div id="pg-shield">Shield</div>
        <h1 id="pg-title">Phishing Website Detected</h1>
        <p id="pg-confidence">${confidenceText}</p>
        <p id="pg-desc">
          This page has been identified as a <strong>phishing website</strong>
          by PhishGuard's machine learning engine.<br><br>
          It may be attempting to steal your passwords, financial details,
          or personal information. <strong>Do not enter any data.</strong>
        </p>
        <div id="pg-url-box" title="${window.location.href}">
          ${window.location.href}
        </div>
        <div id="pg-actions">
          <button id="pg-back-btn">Go Back to Safety</button>
          <button id="pg-safe-mode-btn">Continue in Safe Mode</button>
        </div>
        <p id="pg-footer">PhishGuard · ML-powered phishing detection</p>
      </div>
    `;

    const styleTag = document.createElement('style');
    styleTag.id = STYLE_TAG_ID;
    styleTag.textContent = `
      #pg-box {
        background: #ffffff;
        border-radius: 14px;
        padding: 44px 52px;
        max-width: 580px;
        width: 90%;
        text-align: center;
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.6);
      }
      #pg-shield {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 78px;
        height: 78px;
        margin: 0 auto 14px;
        border-radius: 24px;
        background: linear-gradient(135deg, #fee2e2, #fecaca);
        color: #991b1b;
        font-size: 18px;
        font-weight: 800;
        letter-spacing: 0.04em;
        text-transform: uppercase;
      }
      #pg-title {
        color: #c0392b;
        font-size: 24px;
        font-weight: 800;
        margin: 0 0 6px;
        letter-spacing: -0.4px;
      }
      #pg-confidence {
        color: #e74c3c;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin: 0 0 18px;
      }
      #pg-desc {
        color: #4a4a4a;
        font-size: 15px;
        line-height: 1.65;
        margin: 0 0 20px;
      }
      #pg-url-box {
        background: #fef9f9;
        border: 1px solid #f5b7b1;
        border-radius: 6px;
        padding: 8px 14px;
        font-size: 11px;
        color: #999;
        word-break: break-all;
        margin-bottom: 24px;
        max-height: 48px;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      #pg-actions {
        display: flex;
        gap: 14px;
        justify-content: center;
        flex-wrap: wrap;
      }
      #pg-back-btn {
        background: #c0392b;
        color: #ffffff;
        border: none;
        border-radius: 7px;
        padding: 13px 30px;
        font-size: 15px;
        font-weight: 700;
        cursor: pointer;
        transition: background 0.2s;
        flex-shrink: 0;
      }
      #pg-back-btn:hover {
        background: #a93226;
      }
      #pg-safe-mode-btn {
        background: #ecf0f1;
        color: #666666;
        border: none;
        border-radius: 7px;
        padding: 13px 30px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
        flex-shrink: 0;
      }
      #pg-safe-mode-btn:hover {
        background: #dfe6e9;
      }
      #pg-footer {
        color: #c0c0c0;
        font-size: 11px;
        margin-top: 22px;
        margin-bottom: 0;
      }
    `;

    document.head.appendChild(styleTag);
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    document.getElementById('pg-back-btn').addEventListener('click', () => {
      window.history.back();
    });

    document.getElementById('pg-safe-mode-btn').addEventListener('click', () => {
      enableSafeMode();
      overlay.remove();
      styleTag.remove();
      document.body.style.overflow = '';
      updateScanBadge('phishing', 'Safe mode enabled');
      console.warn(`${LOG} User continued in safe mode on a phishing page.`);
    });

    console.warn(`${LOG} Warning overlay injected - phishing detected.`);
  }

  console.log(`${LOG} Content script loaded on: ${window.location.href}`);
  ensureScanBadge();
  updateScanBadge('scanning');

  try {
    const features = extractFeatures();
    const response = await sendMessageAsync({
      type: 'CHECK_URL',
      features,
      url: window.location.href,
    });

    if (!response) {
      console.warn(`${LOG} No response received from background service worker.`);
      updateScanBadge('error', 'Scan unavailable');
      return;
    }

    console.log(`${LOG} API response:`, response);

    if (response.result === 1) {
      updateScanBadge('phishing', 'Phishing detected');
      injectWarningOverlay(response.probability);
    } else {
      updateScanBadge('safe', 'Safe');
      console.log(`${LOG} Page appears legitimate (result=${response.result}).`);
    }
  } catch (err) {
    console.error(`${LOG} Error during phishing check:`, err.message);
    updateScanBadge('error', 'Scan failed');
  }
})();
