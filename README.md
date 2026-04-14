# PhishGuard

PhishGuard is a machine-learning-powered phishing detection project with two parts:

- A Chrome extension frontend that scans the current page and shows a warning UI.
- A lightweight backend that receives extracted features, enriches them with server-side checks, and returns a phishing prediction.

## Project Structure

```text
backend/
  app.py                 Lambda-ready backend entrypoint + local dev server
  requirements.txt       Lean runtime dependencies
  phishing_model.json    Native XGBoost model for deployment
  phishing_model.pkl     Original training/export artifact

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

The local backend runs on `http://localhost:5000`.

Useful endpoints:

- `GET /health` for a health check
- `POST /predict` for phishing prediction

## Backend Deployment

The backend is structured for AWS Lambda-style deployment.

- Lambda handler: `backend/app.lambda_handler`
- Vercel Flask entrypoint: `app.py` at the repository root
- Runtime model artifact: `backend/phishing_model.json`
- Runtime dependencies: `backend/requirements.txt`

This backend was slimmed down for serverless packaging:

- It loads the native XGBoost model directly instead of unpickling a `scikit-learn` wrapper.
- It no longer requires `scikit-learn`, `joblib`, `Flask`, or `Flask-CORS` at runtime.
- Local development still works with `python app.py`.

This change is specifically intended to reduce deployment size for Lambda/serverless environments where unpacked dependency size is constrained.

### Vercel Notes

Vercel detects Flask from a root-level `app.py` exporting `app = Flask(__name__)`.

- Root Flask entrypoint: `app.py`
- Root dependency file for Vercel: `requirements.txt`
- Shared prediction logic remains in `backend/app.py`

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
2. The background service worker sends those features and the current URL to the backend.
3. The backend adds SSL, WHOIS, and DNS-based checks, then runs the ML model.
4. The extension shows either a safe result or a phishing warning with an optional safe mode.

## Development Notes

- The extension expects the backend at `http://localhost:5000/predict` during local development.
- If the backend is unavailable, the extension falls back to a non-blocking safe result.
- Rebuild the frontend after popup, manifest, or script changes with `npm run build`.

## Repository Hygiene

The `.gitignore` excludes local virtual environments, Python cache files, `frontend/node_modules`, and `frontend/dist` so generated files do not get committed.
