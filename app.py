from flask import Flask, jsonify, request

from backend.app import health_payload, run_prediction


app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify(health_payload())


@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({"ok": True})

    body = request.get_json(force=True, silent=True)
    status, payload = run_prediction(body)
    return jsonify(payload), status
