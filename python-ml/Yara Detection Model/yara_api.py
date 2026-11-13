from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from yaradetect.core import load_rules_from_dir, scan_file

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_RULES_DIR = BASE_DIR / "Rules"
_rules_cache: dict[str, Any] = {}


def _load_rules_cached(rules_dir: Path):
    key = str(rules_dir.resolve())
    if key in _rules_cache:
        return _rules_cache[key]
    rules = load_rules_from_dir(rules_dir)
    _rules_cache[key] = rules
    return rules


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "yara-detection",
        "defaultRulesDir": str(DEFAULT_RULES_DIR),
    })


@app.route("/api/scan-file", methods=["POST"])
@app.route("/api/yara/scan-file", methods=["POST"])
def scan_file_api():
    try:
        body = request.get_json(silent=True) or {}
        file_path_raw = body.get("filePath")
        if not file_path_raw:
            return jsonify({"error": "filePath is required"}), 400

        rules_dir_raw = body.get("rulesDir")
        rules_dir = Path(rules_dir_raw).expanduser().resolve() if rules_dir_raw else DEFAULT_RULES_DIR
        file_path = Path(file_path_raw).expanduser().resolve()

        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": f"File not found or not a regular file: {file_path}"}), 400
        if not rules_dir.exists() or not rules_dir.is_dir():
            return jsonify({"error": f"Rules directory not found: {rules_dir}"}), 400

        rules = _load_rules_cached(rules_dir)
        if not rules:
            return jsonify({
                "status": "ok",
                "source": "yara",
                "filePath": str(file_path),
                "rulesDir": str(rules_dir),
                "matched": False,
                "matchCount": 0,
                "matchedRules": [],
                "matches": {},
                "details": {"rulesLoaded": 0},
            }), 200

        result = scan_file(rules, file_path)
        matched_rules = result.get("matched_rules", [])

        return jsonify({
            "status": "ok",
            "source": "yara",
            "filePath": str(file_path),
            "rulesDir": str(rules_dir),
            "matched": len(matched_rules) > 0,
            "matchCount": len(matched_rules),
            "matchedRules": matched_rules,
            "matches": result.get("matches", {}),
            "details": {"rulesLoaded": len(rules)},
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
