"""Flask entry point for the PhishGuard educational mini project."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from analyzer import RISK_WEIGHTS, analyse_email
from report_generator import create_report
from utils import normalise_form_data, validate_email_input


BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
SAMPLE_FILES = {
    "legitimate": "legitimate_email.json",
    "suspicious": "suspicious_email.json",
    "phishing": "phishing_email.json",
}


def _load_sample(sample_id: str) -> dict[str, Any]:
    filename = SAMPLE_FILES.get(sample_id)
    if not filename:
        abort(404)
    with (SAMPLES_DIR / filename).open(encoding="utf-8") as sample_file:
        return json.load(sample_file)


def _sample_summaries() -> list[dict[str, str]]:
    summaries = []
    for sample_id in SAMPLE_FILES:
        sample = _load_sample(sample_id)
        summaries.append(
            {
                "id": sample_id,
                "name": str(sample["name"]),
                "expected_risk_category": str(
                    sample["expected_risk_category"]
                ),
                "explanation": str(sample["explanation"]),
            }
        )
    return summaries


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the local Flask application."""
    application = Flask(__name__)
    application.config.from_mapping(
        MAX_CONTENT_LENGTH=int(
            os.environ.get("PHISHGUARD_MAX_CONTENT_LENGTH", 32_768)
        ),
        TEMPLATES_AUTO_RELOAD=os.environ.get(
            "PHISHGUARD_TEMPLATE_RELOAD", "0"
        )
        == "1",
    )
    secret_key = os.environ.get("PHISHGUARD_SECRET_KEY")
    if secret_key:
        application.config["SECRET_KEY"] = secret_key
    if test_config:
        application.config.update(test_config)

    @application.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            samples=_sample_summaries(),
            form_data={},
            errors=[],
        )

    @application.post("/analyze")
    def analyze() -> tuple[str, int] | str:
        cleaned, errors = validate_email_input(request.form)
        if errors:
            return (
                render_template(
                    "index.html",
                    samples=_sample_summaries(),
                    form_data=cleaned,
                    errors=errors,
                ),
                400,
            )
        result = analyse_email(cleaned)
        return render_template(
            "result.html",
            result=result,
            email=cleaned,
        )

    @application.get("/api/samples/<sample_id>")
    def sample_api(sample_id: str) -> Response:
        sample = _load_sample(sample_id)
        return jsonify(sample)

    @application.get("/awareness")
    def awareness() -> str:
        return render_template("awareness.html")

    @application.get("/about")
    def about() -> str:
        return render_template("about.html", risk_weights=RISK_WEIGHTS)

    @application.post("/download-report")
    def download_report() -> Response | tuple[str, int]:
        cleaned, errors = validate_email_input(request.form)
        if errors:
            return (
                render_template(
                    "index.html",
                    samples=_sample_summaries(),
                    form_data=cleaned,
                    errors=errors,
                ),
                400,
            )
        result = analyse_email(cleaned)
        filename, report_text = create_report(cleaned, result)
        response = Response(
            report_text,
            mimetype="text/plain",
        )
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )
        return response

    @application.get("/reset")
    def reset() -> Response:
        return redirect(url_for("index"))

    @application.errorhandler(413)
    def input_too_large(_: Exception) -> tuple[str, int]:
        return (
            render_template(
                "index.html",
                samples=_sample_summaries(),
                form_data=normalise_form_data({}),
                errors=["The submitted sample is larger than the allowed limit."],
            ),
            413,
        )

    return application


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("PHISHGUARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("PHISHGUARD_PORT", "5000")),
        debug=os.environ.get("PHISHGUARD_DEBUG", "0") == "1",
    )
