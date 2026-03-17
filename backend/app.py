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


def check_ssl(url: str, domain: str) -> int:
    """
    Compute SSLfinal_State using the dataset's three-state encoding.

    1  => HTTPS with a successful verified handshake
    0  => HTTPS is present but certificate/handshake looks suspicious
   -1  => Not HTTPS
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        logger.debug(f"SSL: no HTTPS for {domain}")
        return -1

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain):
                pass
        logger.debug(f"SSL: valid for {domain}")
        return 1
    except Exception as exc:
        logger.debug(f"SSL: suspicious for {domain} - {exc}")
        return 0


def check_domain_registration_length(domain: str) -> int:
    """
    Return 1 if the domain registration expires more than one year from now.
    Otherwise return -1.
    """
    if not WHOIS_AVAILABLE:
        return -1
    try:
        info = python_whois.whois(domain)
        exp_date = info.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date is None:
            return -1
        if exp_date.tzinfo is None:
            exp_date = exp_date.replace(tzinfo=timezone.utc)
        remaining_days = (exp_date - datetime.now(timezone.utc)).days
        result = 1 if remaining_days > 365 else -1
        logger.debug(f"RegLen: {remaining_days}d remaining for {domain} -> {result}")
        return result
    except Exception as exc:
        logger.debug(f"RegLen: WHOIS failed for {domain} - {exc}")
        return -1


def check_age_of_domain(domain: str) -> int:
    """Return 1 if the domain is older than 6 months, else -1."""
    if not WHOIS_AVAILABLE:
        return -1
    try:
        info = python_whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        result = 1 if age_days > 180 else -1
        logger.debug(f"DomainAge: {age_days}d old for {domain} -> {result}")
        return result
    except Exception as exc:
        logger.debug(f"DomainAge: WHOIS failed for {domain} - {exc}")
        return -1


def check_dns_record(domain: str) -> int:
    """Return 1 if the domain has an A record, else -1."""
    if not DNS_AVAILABLE:
        return -1
    try:
        dns.resolver.resolve(domain, "A")
        logger.debug(f"DNS: A record found for {domain}")
        return 1
    except Exception as exc:
        logger.debug(f"DNS: no A record for {domain} - {exc}")
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

    logger.debug(f"/predict url={url} domain={domain}")
    logger.debug(f"Extension features ({len(ext_features)}): {ext_features}")

    if not isinstance(ext_features, dict):
        return jsonify({"error": "'features' must be a JSON object."}), 400

    try:
        ext_features = normalize_feature_payload(ext_features)
    except ValueError as exc:
        logger.warning(f"Invalid feature payload: {exc}")
        return jsonify({"error": str(exc)}), 400

    server_features = {
        "SSLfinal_State": check_ssl(url, domain),
        "Domain_registeration_length": check_domain_registration_length(domain),
        "age_of_domain": check_age_of_domain(domain),
        "DNSRecord": check_dns_record(domain),
    }
    logger.debug(f"Server features: {server_features}")

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
    logger.debug(f"Feature vector ({len(feature_vector)}): {feature_vector}")

    try:
        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        raw_prediction = model.predict(X)[0]
        logger.debug(f"raw_prediction = {raw_prediction}")

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

        logger.info(
            f"result={result} probability={probability:.4f} "
            f"raw={raw_prediction} domain={domain}"
        )
        return jsonify({"result": result, "probability": probability})

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
