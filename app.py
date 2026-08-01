from flask import Flask, render_template, request
from modules.recon import get_domain_info
from modules.port_scanner import scan_ports
from modules.web_scanner import check_headers
from modules.password_analyzer import analyze_password
from modules.report_generator import generate_report

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():

    target = request.form['target']
    password = request.form['password']

    recon = get_domain_info(target)
    ports = scan_ports(target)
    headers = check_headers(target)
    password_strength = analyze_password(password)

    report_file = generate_report(target, recon, ports, headers)

    return render_template(
        "result.html",
        target=target,
        recon=recon,
        ports=ports,
        headers=headers,
        password_strength=password_strength,
        report=report_file
    )

if __name__ == "__main__":
    app.run(debug=True)