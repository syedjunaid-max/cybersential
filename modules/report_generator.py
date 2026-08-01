from reportlab.pdfgen import canvas
import datetime
import os

def generate_report(target, recon, ports, headers):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/report_{target}.pdf"

    c = canvas.Canvas(filename)

    c.drawString(50, 800, "Red Team Scan Report")

    c.drawString(50, 770, f"Target: {target}")

    c.drawString(50, 740, f"Date: {datetime.datetime.now()}")

    y = 700

    c.drawString(50, y, "Recon Information:")
    y -= 20

    for key, value in recon.items():
        c.drawString(60, y, f"{key}: {value}")
        y -= 20

    c.drawString(50, y, "Open Ports:")
    y -= 20

    for p in ports[:10]:
        c.drawString(60, y, f"Port {p['port']} : {p['state']}")
        y -= 20

    c.drawString(50, y, "Security Headers:")
    y -= 20

    for h, v in headers.items():
        c.drawString(60, y, f"{h} : {v}")
        y -= 20

    c.save()

    return filename