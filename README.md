# PhishGuard

PhishGuard is a machine-learning-powered phishing detection project with two parts:

- A Chrome extension frontend that scans the current page and shows a warning UI.
- A Flask backend that receives extracted features, enriches them with server-side checks, and returns a phishing prediction.

## Project Structure

```text
backend/
  app.py                 Flask API for prediction and health checks
  requirements.txt       Python dependencies
  phishing_model.pkl     Trained ML model

frontend/
  manifest.json          Chrome extension manifest
  background.js          Service worker that calls the backend
  content.js             Content script that extracts features and injects warnings
  utils.js               Feature extraction helpers
  popup/                 React popup UI
  vite.config.js         Vite build config for the extension
```

## Requirements

- Python 3.10+
- Node.js 18+
- Google Chrome or another Chromium-based browser

## Backend Setup

From the `backend` folder:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The Flask API runs on `http://localhost:5000`.

Useful endpoints:

- `GET /health` for a health check
- `POST /predict` for phishing prediction

## Frontend Setup

From the `frontend` folder:

```powershell
npm install
npm run build
```

This creates the unpacked extension build in `frontend/dist`.

## Load the Extension in Chrome

1. Open `chrome://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the `frontend/dist` folder

## How It Works

1. The content script runs on page load and extracts phishing-related features from the URL and DOM.
2. The background service worker sends those features and the current URL to the Flask backend.
3. The backend adds SSL, WHOIS, and DNS-based checks, then runs the ML model.
4. The extension shows either a safe result or a phishing warning with an optional safe mode.

## Development Notes

- The extension expects the backend at `http://localhost:5000/predict`.
- If the backend is unavailable, the extension falls back to a non-blocking safe result.
- Rebuild the frontend after popup, manifest, or script changes with `npm run build`.

## Repository Hygiene

The `.gitignore` excludes local virtual environments, Python cache files, `frontend/node_modules`, and `frontend/dist` so generated files do not get committed.
