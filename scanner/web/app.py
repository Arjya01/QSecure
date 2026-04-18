"""
Q-Secure | web/app.py
Flask testing interface — port 5001.
GET  /              → index.html
POST /scan          → {hostname, port, surfaces, mock} → ScanResult JSON
GET  /mock-profiles → list of profiles with metadata
POST /batch-scan    → {hostnames[], port, surfaces, mock} → list of results
"""

from __future__ import annotations

import sys
import os

# Allow importing scanner package from parent directory
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from flask import Flask, request, jsonify, render_template

import scanner as sc

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/mock-profiles")
def mock_profiles():
    meta = sc.get_mock_profile_meta()
    profiles = []
    for hostname, info in meta.items():
        profiles.append({
            "hostname": hostname,
            "label": info["label"],
            "tags": info["tags"],
        })
    return jsonify({"profiles": profiles})


@app.route("/scan", methods=["POST"])
def do_scan():
    data = request.get_json(force=True, silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname is required"}), 400

    port     = int(data.get("port") or 443)
    mock     = data.get("mock")        # None / true / false
    surfaces = data.get("surfaces")    # dict or None

    # Parse mock param — can be bool or string "true"/"false"
    if isinstance(mock, str):
        mock = mock.lower() == "true"

    try:
        result = sc.scan(hostname, port, surfaces=surfaces, mock=mock)
        return jsonify(result.to_dict())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/batch-scan", methods=["POST"])
def do_batch_scan():
    data = request.get_json(force=True, silent=True) or {}
    hostnames = data.get("hostnames") or []
    if not hostnames or not isinstance(hostnames, list):
        return jsonify({"error": "hostnames array is required"}), 400

    port     = int(data.get("port") or 443)
    mock     = data.get("mock")
    surfaces = data.get("surfaces")

    if isinstance(mock, str):
        mock = mock.lower() == "true"

    try:
        results = sc.batch_scan(hostnames, port, surfaces=surfaces, mock=mock)
        return jsonify({"results": [r.to_dict() for r in results]})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    print("=" * 60)
    print("  Q-Secure Scanner Web Interface")
    print("  http://localhost:5001")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001, debug=True)
