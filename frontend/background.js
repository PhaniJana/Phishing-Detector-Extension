/**
 * background.js - PhishGuard Service Worker (Manifest V3)
 *
 * Acts as the bridge between the content script and the Flask ML backend.
 * Responsibilities:
 *   1. Receive feature payloads from content.js via chrome.runtime.onMessage
 *   2. Forward features + URL to the Flask API at http://localhost:5000/predict
 *   3. Store the scan result in chrome.storage.local (keyed by tab ID)
 *   4. Return the API result to content.js so it can decide to show the overlay
 *
 * Fail-safe policy: if the API is unreachable, we return
 * { result: 0 } (treat as legitimate) so we never block users on a backend outage.
 */

'use strict';

const API_ENDPOINT = 'http://localhost:5000/predict';

/**
 * Sends the extracted features and the page URL to the Flask phishing API.
 * Returns a result object: { result: 0|1, probability: float }.
 * On any error, returns the safe fallback { result: 0, probability: 0 }.
 *
 * @param {Object} features
 * @param {string} url
 * @returns {Promise<{result: number, probability: number, error?: string}>}
 */
async function callPhishingAPI(features, url) {
  try {
    console.log('[PhishGuard BG] Sending features to API for URL:', url);
    console.debug('[PhishGuard BG] Feature payload:', features);

    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features, url }),
    });

    if (!response.ok) {
      throw new Error(`Flask API returned HTTP ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log('[PhishGuard BG] API result:', data);
    return data;
  } catch (err) {
    console.error('[PhishGuard BG] API call failed:', err.message);
    console.error('[PhishGuard BG] Make sure the Flask server is running: python app.py');

    return { result: 0, probability: 0, error: err.message };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'CHECK_URL') return false;

  (async () => {
    const apiResult = await callPhishingAPI(message.features, message.url);

    if (sender.tab && sender.tab.id) {
      const storageKey = `scan_${sender.tab.id}`;
      await chrome.storage.local.set({
        [storageKey]: {
          result: apiResult.result,
          probability: apiResult.probability,
          verdict: apiResult.verdict || (apiResult.result === 1 ? 'phish' : 'safe'),
          url: message.url,
          timestamp: Date.now(),
        },
      });
      console.log(`[PhishGuard BG] Stored scan result for tab ${sender.tab.id}:`, apiResult);
    }

    sendResponse(apiResult);
  })();

  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`scan_${tabId}`);
});

console.log('[PhishGuard BG] Service worker initialised.');
