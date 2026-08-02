"""Flask routes and orchestration for the Cybersential project."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_from_directory, url_for

from services.header_analyzer import analyze_security_headers
from services.password_analyzer import analyze_password
from services.packet_inspector import (
    DEFAULT_CAPTURE_DURATION,
    DEFAULT_PACKET_LIMIT,
    PacketInspectionError,
    capture_packets,
    get_capture_environment,
)
from services.port_scanner import scan_tcp_ports
from services.reconnaissance import TargetValidationError, normalize_assessment_target, perform_reconnaissance
from services.report_generator import (
    dpi_report_path_for_capture_id,
    generate_assessment_report,
    generate_dpi_report,
    report_path_for_scan_id,
)
from services.traffic_analyzer import DPIResultStore, MAX_DPI_RESULTS, analyze_traffic


BASE_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIRECTORY = BASE_DIRECTORY / "reports"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=16 * 1024,
        REPORTS_DIRECTORY=str(DEFAULT_REPORTS_DIRECTORY),
        MAX_DPI_RESULTS=MAX_DPI_RESULTS,
    )
    if test_config:
        app.config.update(test_config)
    app.extensions["dpi_results"] = DPIResultStore(app.config["MAX_DPI_RESULTS"])

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

    @app.get("/dpi")
    def dpi():
        return render_template(
            "dpi.html",
            capture_environment=get_capture_environment(),
            default_duration=DEFAULT_CAPTURE_DURATION,
            default_packet_limit=DEFAULT_PACKET_LIMIT,
        )

    @app.post("/dpi/capture")
    def dpi_capture():
        submitted = {
            "interface": request.form.get("interface", ""),
            "duration": request.form.get("duration", str(DEFAULT_CAPTURE_DURATION)),
            "packet_limit": request.form.get("packet_limit", str(DEFAULT_PACKET_LIMIT)),
        }
        authorization_confirmed = request.form.get("authorized") == "yes"
        if not authorization_confirmed:
            return (
                render_template(
                    "dpi.html",
                    capture_environment=get_capture_environment(),
                    capture_error="Confirm that you own this machine and network or have explicit permission to capture this traffic.",
                    capture_error_code="authorization_required",
                    submitted=submitted,
                    default_duration=DEFAULT_CAPTURE_DURATION,
                    default_packet_limit=DEFAULT_PACKET_LIMIT,
                ),
                403,
            )
        try:
            capture = capture_packets(
                interface=submitted["interface"],
                duration=submitted["duration"],
                packet_limit=submitted["packet_limit"],
                authorization_confirmed=authorization_confirmed,
            )
        except PacketInspectionError as exc:
            return (
                render_template(
                    "dpi.html",
                    capture_environment=get_capture_environment(),
                    capture_error=exc.message,
                    capture_error_code=exc.code,
                    submitted=submitted,
                    default_duration=DEFAULT_CAPTURE_DURATION,
                    default_packet_limit=DEFAULT_PACKET_LIMIT,
                ),
                exc.status_code,
            )

        packet_metadata = capture.pop("packets", [])
        try:
            assessment = analyze_traffic(
                packet_metadata,
                selected_interface=capture["interface_name"],
                capture_duration_seconds=capture["capture_duration_seconds"],
                requested_duration_seconds=capture["requested_duration_seconds"],
                packet_limit=capture["packet_limit"],
                authorization_confirmed=True,
                started_at=capture["started_at"],
                completed_at=capture["completed_at"],
            )
        except Exception:
            app.logger.exception("The captured metadata could not be summarized safely.")
            return (
                render_template(
                    "dpi.html",
                    capture_environment=get_capture_environment(),
                    capture_error="The capture completed, but its approved metadata could not be summarized safely.",
                    capture_error_code="analysis_failed",
                    submitted=submitted,
                    default_duration=DEFAULT_CAPTURE_DURATION,
                    default_packet_limit=DEFAULT_PACKET_LIMIT,
                ),
                500,
            )
        capture_id = str(uuid.uuid4())
        assessment["capture_id"] = capture_id
        try:
            generate_dpi_report(
                assessment=assessment,
                authorization_confirmed=True,
                reports_directory=app.config["REPORTS_DIRECTORY"],
                capture_id=capture_id,
            )
            assessment["report_available"] = True
        except Exception:
            app.logger.exception("The metadata-only DPI PDF report could not be generated.")
            assessment["report_error"] = "The traffic analysis completed, but its PDF report could not be generated."

        app.extensions["dpi_results"].add(assessment, capture_id)
        return redirect(url_for("dpi_result", capture_id=capture_id), code=303)

    @app.get("/dpi/result/<capture_id>")
    def dpi_result(capture_id: str):
        assessment = app.extensions["dpi_results"].get(capture_id)
        if assessment is None:
            abort(404)
        return render_template("dpi_result.html", assessment=assessment, capture_id=capture_id)

    @app.get("/dpi/reports/<capture_id>/download")
    def download_dpi_report(capture_id: str):
        assessment = app.extensions["dpi_results"].get(capture_id)
        if assessment is None or not assessment.get("report_available"):
            abort(404)
        try:
            report_path = dpi_report_path_for_capture_id(capture_id, app.config["REPORTS_DIRECTORY"])
        except ValueError:
            abort(404)
        if not report_path.is_file():
            abort(404)
        return send_from_directory(
            report_path.parent,
            report_path.name,
            as_attachment=True,
            download_name=f"Cybersential_DPI_Report_{capture_id}.pdf",
            max_age=0,
        )

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
