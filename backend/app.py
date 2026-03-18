"""
PhishGuard Flask backend API.

POST /predict
    Body: {"features": {...}, "url": "https://..."}
    Returns: {"result": 0|1, "probability": float}
    result 1 = phishing, result 0 = legitimate

GET /health
    Returns backend health and dependency status.
"""

import os
import ssl
import socket
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import numpy as np
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

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
    logging.warning(
        "dnspython not installed. "
        "DNSRecord will default to -1."
    )


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)


MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "phishing_model.pkl",
)
model_load_error = None
phishing_class_value = 0
PHISH_THRESHOLD = 0.60
DOUBT_THRESHOLD = 0.20


try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded from: {MODEL_PATH}")
    logger.info(f"  Type   : {type(model).__name__}")
    if hasattr(model, "classes_"):
        logger.info(f"  Classes: {model.classes_}")
    if hasattr(model, "n_features_in_"):
        logger.info(f"  Expects: {model.n_features_in_} features")
    logger.info(f"  Phishing class value fixed as: {phishing_class_value}")
except Exception as exc:
    logger.critical(f"Failed to load model from {MODEL_PATH}: {exc}")
    model = None
    model_load_error = str(exc)


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


def extract_domain(url: str) -> str:
    """Return the hostname from a URL string, or an empty string on failure."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def is_timeout_error(exc: Exception) -> bool:
    """Return True when an exception appears to be timeout-related."""
    text = str(exc).lower()
    return isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text


def check_ssl(url: str, domain: str) -> int:
    """
    Compute SSLfinal_State using the dataset's three-state encoding.

    1  => HTTPS with a successful verified handshake
    0  => HTTPS is present but certificate/handshake looks suspicious
   -1  => Not HTTPS
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        logger.debug(f"[SSL] {domain}: skipped because URL is not HTTPS -> -1")
        return -1

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain):
                pass
        logger.debug(f"[SSL] {domain}: verified TLS handshake succeeded -> 1")
        return 1
    except Exception as exc:
        reason = "timeout during TLS handshake" if is_timeout_error(exc) else exc
        logger.debug(f"[SSL] {domain}: HTTPS present but verification failed ({reason}) -> 0")
        return 0


def check_domain_registration_length(domain: str) -> int:
    """
    Return 1 if the domain registration expires more than one year from now.
    Otherwise return -1.
    """
    if not WHOIS_AVAILABLE:
        logger.debug(f"[WHOIS RegLen] {domain}: skipped because python-whois is unavailable -> -1")
        return -1
    try:
        info = python_whois.whois(domain)
        exp_date = info.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date is None:
            logger.debug(f"[WHOIS RegLen] {domain}: expiration date missing -> -1")
            return -1
        if exp_date.tzinfo is None:
            exp_date = exp_date.replace(tzinfo=timezone.utc)
        remaining_days = (exp_date - datetime.now(timezone.utc)).days
        result = 1 if remaining_days > 365 else -1
        logger.debug(f"[WHOIS RegLen] {domain}: {remaining_days}d remaining -> {result}")
        return result
    except Exception as exc:
        reason = "WHOIS lookup timed out" if is_timeout_error(exc) else f"WHOIS lookup failed ({exc})"
        logger.debug(f"[WHOIS RegLen] {domain}: {reason} -> -1")
        return -1


def check_age_of_domain(domain: str) -> int:
    """Return 1 if the domain is older than 6 months, else -1."""
    if not WHOIS_AVAILABLE:
        logger.debug(f"[WHOIS Age] {domain}: skipped because python-whois is unavailable -> -1")
        return -1
    try:
        info = python_whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            logger.debug(f"[WHOIS Age] {domain}: creation date missing -> -1")
            return -1
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        result = 1 if age_days > 180 else -1
        logger.debug(f"[WHOIS Age] {domain}: {age_days}d old -> {result}")
        return result
    except Exception as exc:
        reason = "WHOIS lookup timed out" if is_timeout_error(exc) else f"WHOIS lookup failed ({exc})"
        logger.debug(f"[WHOIS Age] {domain}: {reason} -> -1")
        return -1


def check_dns_record(domain: str) -> int:
    """Return 1 if the domain has an A record, else -1."""
    if not DNS_AVAILABLE:
        logger.debug(f"[DNS] {domain}: skipped because dnspython is unavailable -> -1")
        return -1
    try:
        dns.resolver.resolve(domain, "A")
        logger.debug(f"[DNS] {domain}: A record found -> 1")
        return 1
    except Exception as exc:
        reason = "DNS lookup timed out" if is_timeout_error(exc) else f"no A record / lookup failed ({exc})"
        logger.debug(f"[DNS] {domain}: {reason} -> -1")
        return -1


def normalize_feature_value(name: str, value):
    """
    Enforce the exact dataset encoding expected by the model.

    We intentionally reject booleans and arbitrary numerics instead of
    guessing a conversion because feature semantics differ by column.
    """
    if isinstance(value, bool):
        raise ValueError(
            f"{name} must be encoded as -1, 0, or 1, not boolean {value!r}"
        )

    if isinstance(value, str):
        stripped = value.strip()
        if stripped in {"-1", "0", "1"}:
            return int(stripped)
        raise ValueError(f"{name} must be encoded as -1, 0, or 1, not {value!r}")

    if isinstance(value, (int, float)) and value in (-1, 0, 1):
        return int(value)

    raise ValueError(f"{name} must be encoded as -1, 0, or 1, not {value!r}")


def normalize_feature_payload(ext_features: dict) -> dict:
    """Validate the full extension payload before building the feature vector."""
    normalized = {}
    for name, value in ext_features.items():
        normalized[name] = normalize_feature_value(name, value)
    return normalized


def classify_verdict(probability: float) -> str:
    """Map phishing probability to a user-facing verdict label."""
    if probability >= PHISH_THRESHOLD:
        return "phish"
    if probability >= DOUBT_THRESHOLD:
        return "doubt"
    return "safe"


@app.route("/predict", methods=["POST"])
def predict():
    """Run phishing prediction for a URL plus extension-provided features."""
    if model is None:
        logger.error("Prediction requested but model is not loaded.")
        return jsonify({
            "error": "Model not loaded - check server logs.",
            "detail": model_load_error,
        }), 503

    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    ext_features = body.get("features", {})
    url = body.get("url", "")
    domain = extract_domain(url)

    start = time.perf_counter()
    logger.debug(f"[Predict] start url={url} domain={domain}")
    logger.debug(f"[Predict] extension features ({len(ext_features)}): {ext_features}")

    if not isinstance(ext_features, dict):
        return jsonify({"error": "'features' must be a JSON object."}), 400

    try:
        ext_features = normalize_feature_payload(ext_features)
    except ValueError as exc:
        logger.warning(f"Invalid feature payload: {exc}")
        return jsonify({"error": str(exc)}), 400

    logger.debug(f"[Predict] deriving server-side features for {domain}")
    server_features = {
        "SSLfinal_State": check_ssl(url, domain),
        "Domain_registeration_length": check_domain_registration_length(domain),
        "age_of_domain": check_age_of_domain(domain),
        "DNSRecord": check_dns_record(domain),
    }
    logger.debug(f"[Predict] server features: {server_features}")

    all_features = {**ext_features, **server_features}
    all_features.setdefault("Favicon", 1)

    missing = [feature for feature in FEATURE_ORDER if feature not in all_features]
    if missing:
        logger.warning(f"Missing features: {missing}")
        return jsonify({
            "error": "Missing required features in request payload.",
            "missing_features": missing,
        }), 400

    feature_vector = [all_features[feature] for feature in FEATURE_ORDER]
    logger.debug(f"[Predict] feature vector ({len(feature_vector)}): {feature_vector}")

    try:
        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        raw_prediction = model.predict(X)[0]
        logger.debug(f"[Predict] raw_prediction={raw_prediction}")

        result = 1 if int(raw_prediction) == 0 else 0

        probability = 0.0
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)[0]
            classes = list(model.classes_)
            if phishing_class_value in classes:
                phishing_idx = classes.index(phishing_class_value)
            else:
                phishing_idx = len(classes) - 1
            probability = float(proba[phishing_idx])

        verdict = classify_verdict(probability)

        logger.info(
            f"[Predict] completed domain={domain} result={result} verdict={verdict} "
            f"probability={probability:.4f} raw={raw_prediction} "
            f"elapsed_ms={(time.perf_counter() - start) * 1000:.0f}"
        )
        return jsonify({
            "result": result,
            "probability": probability,
            "verdict": verdict,
            "thresholds": {
                "doubt": DOUBT_THRESHOLD,
                "phish": PHISH_THRESHOLD,
            },
        })

    except Exception as exc:
        logger.error(f"Prediction error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Simple health-check endpoint for diagnostics."""
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "model_error": model_load_error,
        "whois": WHOIS_AVAILABLE,
        "dns": DNS_AVAILABLE,
    })


if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("PhishGuard API - http://localhost:5000")
    logger.info("Endpoints: POST /predict   GET /health")
    logger.info("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
