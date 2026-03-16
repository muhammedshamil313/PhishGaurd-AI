"""
PhishGuard AI — Flask Backend
Run: python app.py
Then open: http://localhost:5000
"""

import os
import sys
import json
import time
import re
import threading

from flask import Flask, render_template, request, jsonify, send_file

# Add current directory to path so analyzer.py is found
sys.path.insert(0, os.path.dirname(__file__))

app = Flask(__name__)

# ── ChromeDriver path — already set for your machine ─────────────────────────
CHROMEDRIVER_PATH = r"C:\Users\shami\Downloads\chromedriver-win64 (1)\chromedriver-win64\chromedriver.exe"

# In-memory job store
scan_jobs = {}


def run_scan(job_id: str, url: str):
    try:
        from analyzer import SymmetryAnalyzer, CSSAnalyzer
        from report_generator import generate_report

        scan_jobs[job_id]["status"]  = "scanning"
        scan_jobs[job_id]["message"] = "Launching browser..."

        analyzer = SymmetryAnalyzer(headless=True, chromedriver_path=CHROMEDRIVER_PATH)

        scan_jobs[job_id]["message"] = f"Scanning {url} ..."
        report = analyzer.analyze(url)

        # CSS rules from BeautifulSoup
        css_rules = {}
        try:
            from bs4 import BeautifulSoup
            html = analyzer.driver.page_source
            ca = CSSAnalyzer(html)
            css_rules = ca.extract_login_css_rules()
        except Exception:
            pass
        finally:
            analyzer.quit()

        scan_jobs[job_id]["message"] = "Generating PDF report..."
        os.makedirs("reports", exist_ok=True)
        safe = re.sub(r'[^\w]', '_', report.domain)[:30]
        ts   = int(time.time())
        pdf_path = f"reports/report_{safe}_{ts}.pdf"
        generate_report(report, pdf_path, css_rules=css_rules or None)

        scan_jobs[job_id].update({
            "status":    "done",
            "message":   "Complete!",
            "report":    report.to_dict(),
            "pdf_path":  pdf_path,
            "css_rules": {k: v for k, v in list(css_rules.items())[:10]},
        })

    except Exception as e:
        scan_jobs[job_id].update({
            "status":  "error",
            "message": str(e),
        })


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith("http"):
        url = "https://" + url

    job_id = f"job_{int(time.time()*1000)}"
    scan_jobs[job_id] = {"status": "pending", "message": "Starting..."}

    t = threading.Thread(target=run_scan, args=(job_id, url), daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def api_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/download/<job_id>")
def api_download(job_id):
    job = scan_jobs.get(job_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "Report not ready"}), 404
    pdf_path = job.get("pdf_path")
    if not pdf_path or not os.path.exists(pdf_path):
        return jsonify({"error": "PDF not found"}), 404
    return send_file(pdf_path, as_attachment=True, download_name="phishguard_report.pdf")


if __name__ == "__main__":
    print("\n  🛡  PhishGuard AI is running!")
    print("  ► Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000, threaded=True)
