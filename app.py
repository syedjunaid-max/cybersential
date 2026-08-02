"""Flask routes and orchestration for the Cybersential project."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, render_template, request, send_from_directory

from services.header_analyzer import analyze_security_headers
from services.password_analyzer import analyze_password
from services.port_scanner import scan_tcp_ports
from services.reconnaissance import TargetValidationError, normalize_assessment_target, perform_reconnaissance
from services.report_generator import generate_assessment_report, report_path_for_scan_id


BASE_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIRECTORY = BASE_DIRECTORY / "reports"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=16 * 1024,
        REPORTS_DIRECTORY=str(DEFAULT_REPORTS_DIRECTORY),
    )
    if test_config:
        app.config.update(test_config)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.post("/scan")
    def scan():
        raw_target = request.form.get("target", "")
        authorization_confirmed = request.form.get("authorized") == "yes"

        if not authorization_confirmed:
            return (
                render_template(
                    "index.html",
                    assessment_error="Confirm that you own the target or have explicit permission to assess it.",
                    submitted_target=raw_target,
                ),
                403,
            )

        try:
            normalized_target = normalize_assessment_target(raw_target)
        except TargetValidationError as exc:
            return (
                render_template(
                    "index.html",
                    assessment_error=str(exc),
                    submitted_target=raw_target,
                ),
                400,
            )

        scan_host = normalized_target.scan_host
        web_url = normalized_target.web_url

        scan_id = str(uuid.uuid4())
        assessed_at = datetime.now().astimezone()
        try:
            reconnaissance = perform_reconnaissance(scan_host)
            port_scan = scan_tcp_ports(scan_host)
            header_analysis = analyze_security_headers(
                web_url,
                fallback_to_http=normalized_target.fallback_to_http,
            )
        except Exception:
            app.logger.exception("An unexpected assessment service error occurred.")
            return (
                render_template(
                    "index.html",
                    assessment_error="The assessment could not be completed safely. Please try again.",
                    submitted_target=raw_target,
                ),
                500,
            )

        report_available = False
        report_error = None
        try:
            generate_assessment_report(
                target=web_url,
                scan_host=scan_host,
                authorization_confirmed=True,
                reconnaissance=reconnaissance,
                port_scan=port_scan,
                header_analysis=header_analysis,
                reports_directory=app.config["REPORTS_DIRECTORY"],
                scan_id=scan_id,
                assessment_datetime=assessed_at,
            )
            report_available = True
        except Exception:
            app.logger.exception("The PDF report could not be generated.")
            report_error = "The assessment completed, but the PDF report could not be generated."

        return render_template(
            "result.html",
            target=web_url,
            scan_host=scan_host,
            scan_id=scan_id,
            assessed_at=assessed_at.isoformat(),
            authorization_confirmed=True,
            reconnaissance=reconnaissance,
            port_scan=port_scan,
            header_analysis=header_analysis,
            report_available=report_available,
            report_error=report_error,
        )

    @app.post("/password-analysis")
    def password_analysis():
        # The submitted password is used only for this in-memory calculation.
        result = analyze_password(request.form.get("password", ""))
        return render_template("index.html", password_result=result)

    @app.get("/reports/<scan_id>/download")
    def download_report(scan_id: str):
        try:
            report_path = report_path_for_scan_id(scan_id, app.config["REPORTS_DIRECTORY"])
        except ValueError:
            abort(404)
        if not report_path.is_file():
            abort(404)
        return send_from_directory(
            report_path.parent,
            report_path.name,
            as_attachment=True,
            download_name=f"Cybersential_Report_{scan_id}.pdf",
            max_age=0,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", title="Not found", message="The requested page or report was not found."), 404

    @app.errorhandler(413)
    def request_too_large(_error):
        return render_template("error.html", title="Request too large", message="The submitted form was too large."), 413

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template("error.html", title="Request failed", message="The request could not be completed safely."), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
