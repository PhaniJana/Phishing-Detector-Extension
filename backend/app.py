"""
PhishGuard backend entrypoint.

Deployment:
- AWS Lambda handler: `app.lambda_handler`

Local development:
- `python app.py`
- Serves:
    GET /health
    POST /predict
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import numpy as np
import xgboost as xgb

try:
    import whois as python_whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logging.warning(
        "python-whois not installed. "
        "Domain_registeration_length and age_of_domain will default to -1."
    )

try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not installed. DNSRecord will default to -1.")


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "phishing_model.json",
)
model_load_error = None
model: xgb.Booster | None = None
PHISH_THRESHOLD = 0.60
DOUBT_THRESHOLD = 0.20

FEATURE_ORDER = [
    "having_IPhaving_IP_Address",
    "URLURL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "port",
    "HTTPS_token",
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
]

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
}


def load_model() -> xgb.Booster | None:
    global model_load_error

    try:
        booster = xgb.Booster()
        booster.load_model(MODEL_PATH)
        logger.info("Model loaded from: %s", MODEL_PATH)
        model_load_error = None
        return booster
    except Exception as exc:
        model_load_error = str(exc)
        logger.critical("Failed to load model from %s: %s", MODEL_PATH, exc)
        return None


model = load_model()


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def is_timeout_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text


def check_ssl(url: str, domain: str) -> int:
    if not domain:
        return -1

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return -1

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain):
                pass
        return 1
    except Exception as exc:
        reason = "timeout during TLS handshake" if is_timeout_error(exc) else exc
        logger.debug("[SSL] %s: HTTPS present but verification failed (%s) -> 0", domain, reason)
        return 0


def _normalize_whois_datetime(value):
    if isinstance(value, list):
        value = value[0]
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def check_domain_registration_length(domain: str) -> int:
    if not WHOIS_AVAILABLE or not domain:
        return -1
    try:
        info = python_whois.whois(domain)
        exp_date = _normalize_whois_datetime(info.expiration_date)
        if exp_date is None:
            return -1
        remaining_days = (exp_date - datetime.now(timezone.utc)).days
        return 1 if remaining_days > 365 else -1
    except Exception as exc:
        logger.debug("[WHOIS RegLen] %s failed: %s", domain, exc)
        return -1


def check_age_of_domain(domain: str) -> int:
    if not WHOIS_AVAILABLE or not domain:
        return -1
    try:
        info = python_whois.whois(domain)
        creation_date = _normalize_whois_datetime(info.creation_date)
        if creation_date is None:
            return -1
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return 1 if age_days > 180 else -1
    except Exception as exc:
        logger.debug("[WHOIS Age] %s failed: %s", domain, exc)
        return -1


def check_dns_record(domain: str) -> int:
    if not DNS_AVAILABLE or not domain:
        return -1
    try:
        dns.resolver.resolve(domain, "A")
        return 1
    except Exception as exc:
        logger.debug("[DNS] %s failed: %s", domain, exc)
        return -1


def normalize_feature_value(name: str, value) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be encoded as -1, 0, or 1, not boolean {value!r}")

    if isinstance(value, str):
        stripped = value.strip()
        if stripped in {"-1", "0", "1"}:
            return int(stripped)
        raise ValueError(f"{name} must be encoded as -1, 0, or 1, not {value!r}")

    if isinstance(value, (int, float)) and value in (-1, 0, 1):
        return int(value)

    raise ValueError(f"{name} must be encoded as -1, 0, or 1, not {value!r}")


def normalize_feature_payload(ext_features: dict) -> dict:
    return {name: normalize_feature_value(name, value) for name, value in ext_features.items()}


def classify_verdict(probability: float) -> str:
    if probability >= PHISH_THRESHOLD:
        return "phish"
    if probability >= DOUBT_THRESHOLD:
        return "doubt"
    return "safe"


def make_response(status_code: int, payload: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            **CORS_HEADERS,
        },
        "body": json.dumps(payload),
    }


def health_payload() -> dict:
    return {
        "status": "ok",
        "model_loaded": model is not None,
        "model_error": model_load_error,
        "whois": WHOIS_AVAILABLE,
        "dns": DNS_AVAILABLE,
        "runtime": "lambda-ready",
    }


def run_prediction(body: dict) -> tuple[int, dict]:
    if model is None:
        logger.error("Prediction requested but model is not loaded.")
        return 503, {
            "error": "Model not loaded - check server logs.",
            "detail": model_load_error,
        }

    if not body:
        return 400, {"error": "Request body must be valid JSON."}

    ext_features = body.get("features", {})
    url = body.get("url", "")
    domain = extract_domain(url)

    if not isinstance(ext_features, dict):
        return 400, {"error": "'features' must be a JSON object."}

    try:
        ext_features = normalize_feature_payload(ext_features)
    except ValueError as exc:
        return 400, {"error": str(exc)}

    start = time.perf_counter()
    server_features = {
        "SSLfinal_State": check_ssl(url, domain),
        "Domain_registeration_length": check_domain_registration_length(domain),
        "age_of_domain": check_age_of_domain(domain),
        "DNSRecord": check_dns_record(domain),
    }

    all_features = {**ext_features, **server_features}
    all_features.setdefault("Favicon", 1)

    missing = [feature for feature in FEATURE_ORDER if feature not in all_features]
    if missing:
        return 400, {
            "error": "Missing required features in request payload.",
            "missing_features": missing,
        }

    feature_vector = [all_features[feature] for feature in FEATURE_ORDER]

    try:
        matrix = xgb.DMatrix(np.array([feature_vector], dtype=np.float32))
        class1_probability = float(model.predict(matrix)[0])
        phishing_probability = 1.0 - class1_probability
        result = 1 if phishing_probability >= 0.5 else 0
        verdict = classify_verdict(phishing_probability)

        logger.info(
            "[Predict] domain=%s result=%s verdict=%s probability=%.4f elapsed_ms=%.0f",
            domain,
            result,
            verdict,
            phishing_probability,
            (time.perf_counter() - start) * 1000,
        )
        return 200, {
            "result": result,
            "probability": phishing_probability,
            "verdict": verdict,
            "thresholds": {
                "doubt": DOUBT_THRESHOLD,
                "phish": PHISH_THRESHOLD,
            },
        }
    except Exception as exc:
        logger.error("Prediction error: %s", exc, exc_info=True)
        return 500, {"error": str(exc)}


def lambda_handler(event, context):
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    ).upper()
    path = event.get("rawPath") or event.get("path") or "/"

    if method == "OPTIONS":
        return make_response(200, {"ok": True})

    if method == "GET" and path == "/health":
        return make_response(200, health_payload())

    if method == "POST" and path == "/predict":
        raw_body = event.get("body") or ""
        if event.get("isBase64Encoded"):
            return make_response(400, {"error": "Base64-encoded bodies are not supported."})
        try:
            body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            return make_response(400, {"error": "Request body must be valid JSON."})
        status, payload = run_prediction(body)
        return make_response(status, payload)

    return make_response(404, {"error": "Not found"})


class LocalRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        for key, value in CORS_HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self):
        self._send_json(200, {"ok": True})

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, health_payload())
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/predict":
            self._send_json(404, {"error": "Not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
        try:
            body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Request body must be valid JSON."})
            return

        status, payload = run_prediction(body)
        self._send_json(status, payload)

    def log_message(self, format_, *args):
        logger.info("%s - %s", self.address_string(), format_ % args)


def run_local_server() -> None:
    port = int(os.getenv("PORT", "5000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), LocalRequestHandler)
    logger.info("=" * 60)
    logger.info("PhishGuard API - http://localhost:%s", port)
    logger.info("Endpoints: POST /predict   GET /health")
    logger.info("Lambda handler: app.lambda_handler")
    logger.info("=" * 60)
    server.serve_forever()


if __name__ == "__main__":
    run_local_server()
