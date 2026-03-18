import { useEffect, useState } from 'react';

const STATE = {
  scanning: {
    icon: '...',
    label: 'Scanning...',
    sub: 'Analysis in progress',
    className: 'scanning',
  },
  safe: {
    icon: 'OK',
    label: 'Safe',
    sub: 'No phishing detected',
    className: 'safe',
  },
  doubt: {
    icon: '?',
    label: 'Doubtful',
    sub: 'Suspicious signals detected',
    className: 'doubt',
  },
  phishing: {
    icon: '!',
    label: 'Phishing Detected',
    sub: 'Threat identified',
    className: 'phishing',
  },
  unknown: {
    icon: 'i',
    label: 'Not Yet Scanned',
    sub: 'Navigate to a page first',
    className: 'unknown',
  },
};

function formatProbability(probability) {
  const rawPct = Number(probability) * 100;
  const pctBar = Math.max(0, Math.min(100, rawPct));
  const level = pctBar >= 70 ? 'high' : pctBar >= 40 ? 'medium' : 'low';
  const label = rawPct > 0 && rawPct < 0.01 ? '<0.01%' : `${rawPct.toFixed(2)}%`;

  return { level, pctBar, label };
}

function mapVerdictToState(scan) {
  if (!scan) return 'unknown';
  if (scan.verdict === 'phish') return 'phishing';
  if (scan.verdict === 'doubt') return 'doubt';
  if (scan.verdict === 'safe') return 'safe';
  return scan.result === 1 ? 'phishing' : 'safe';
}

export default function App() {
  const [view, setView] = useState({
    state: 'scanning',
    scan: null,
  });

  useEffect(() => {
    let cancelled = false;

    async function loadScan() {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.id) {
          if (!cancelled) {
            setView({ state: 'unknown', scan: null });
          }
          return;
        }

        const key = `scan_${tab.id}`;
        const stored = await chrome.storage.local.get(key);
        const scan = stored[key];

        if (!scan) {
          if (!cancelled) {
            setView({ state: 'unknown', scan: null });
          }
          return;
        }

        if (!cancelled) {
          setView({
            state: mapVerdictToState(scan),
            scan,
          });
        }
      } catch (error) {
        console.error('[PhishGuard Popup] Unexpected error:', error);
        if (!cancelled) {
          setView({ state: 'unknown', scan: null });
        }
      }
    }

    loadScan();
    return () => {
      cancelled = true;
    };
  }, []);

  const current = STATE[view.state] || STATE.unknown;
  const probability = view.scan?.probability != null
    ? formatProbability(view.scan.probability)
    : null;

  return (
    <div className="popup-shell">
      <header className="header">
        <div className="header-badge">PG</div>
        <div>
          <div className="header-title">PhishGuard</div>
          <div className="header-sub">ML-powered phishing detection</div>
        </div>
      </header>

      <main className="card">
        <section className={`status-bar ${current.className}`}>
          <div className="status-icon">{current.icon}</div>
          <div>
            <div className="status-label">{current.label}</div>
            <div className="status-sub">{current.sub}</div>
          </div>
        </section>

        {view.scan && (
          <section className="details">
            <div className="detail-row">
              <span className="detail-label">URL</span>
              <span className="detail-value" title={view.scan.url}>{view.scan.url}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Verdict</span>
              <span className="detail-value">{view.scan.verdict || mapVerdictToState(view.scan)}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Confidence</span>
              <span className={`detail-value pv-${probability?.level || 'low'}`}>
                {probability?.label || '--'}
              </span>
            </div>

            {probability && (
              <div className="prob-bar-wrap">
                <div
                  className={`prob-bar ${probability.level}`}
                  style={{ width: `${probability.pctBar}%` }}
                />
              </div>
            )}

            <div className="detail-row">
              <span className="detail-label">Scanned at</span>
              <span className="detail-value">
                {view.scan.timestamp ? new Date(view.scan.timestamp).toLocaleTimeString() : '--'}
              </span>
            </div>
          </section>
        )}
      </main>

      <footer className="footer">
        <p>Pages are scanned automatically on load.</p>
        <p>Build the extension with Vite, then load `frontend/dist` in Chrome.</p>
      </footer>
    </div>
  );
}
