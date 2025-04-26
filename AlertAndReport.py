import sys
import json
import os
import argparse
import requests
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import hashlib
from pathlib import Path
from dotenv import load_dotenv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import pytz
import logging
import fcntl
from collections import defaultdict, Counter
import re
import math

# Setup logging
logging.basicConfig(
    level=logging.INFO,  # Can be changed to DEBUG for more verbosity
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),  # Console output
        # logging.FileHandler("vuln_report.log")  # Optional file output
    ]
)

logger = logging.getLogger(__name__)


# Lock file to prevent multiple instances
lock_file_path = os.getenv("LOCK_FILE", "/tmp/euvd.lock")
lock_file = open(lock_file_path, "w")

# Choose your timezone (e.g., Europe/Paris or US/Eastern)
timezone = pytz.timezone("Europe/Paris")

# Load environment variables from .env
load_dotenv()

## Define now()
# Get the current date and time
now_local = datetime.now(timezone)
now = datetime.now()
today = now_local.strftime("%Y-%m-%d")
formatted_date = now_local.strftime("%B %d, %Y")
# Format it in full English style
full_date = now.strftime("%A, %B %d, %Y at %I:%M %p %Z")

# === Config from .env ===
VULN_FILE = os.getenv("VULN_FILE", "euvd.json")
KEYWORDS_FILE = os.getenv("KEYWORDS_FILE", "keywords.json")
SENT_IDS_DAILY_FILE = os.getenv("SENT_IDS_DAILY_FILE", "sent_ids_daily.json")
SENT_IDS_ALERT_FILE = os.getenv("SENT_IDS_ALERT_FILE", "sent_ids_alert.json")
WEBHOOK_DAILY_URL = os.getenv("WEBHOOK_DAILY_URL")
WEBHOOK_ALERT_URL = os.getenv("WEBHOOK_ALERT_URL")
MIN_CVSS_TO_ALERT = float(os.getenv("MIN_CVSS_TO_ALERT", 8))
RADAR_FOLDER = os.getenv("RADAR_FOLDER", "./web/radars")
RADAR_URL = os.getenv("RADAR_URL", "https://vuln.mousqueton.io/radar")
DAILY_FOLDER = os.getenv("DAILY_FOLDER", "./web/daily")
DAILY_URL = os.getenv("DAILY_URL", "https://vuln.mousqueton.io/daily")
MONTHLY_URL = os.getenv("MONTHLY_URL", "https://vuln.mousqueton.io/monthly")
MONTHLY_FOLDER = os.getenv("MONTHLY_FOLDER", "./web/monthly")
ALERTS_URL = os.getenv("ALERTS_URL", "https://vuln.mousqueton.io/alerts")
ALERTS_FOLDER = os.getenv("ALERTS_FOLDER", "./web/alerts")
NOVULN = os.getenv("NOVULN", "False").lower() in ("true", "1", "yes")
LOG_FILE_PATH = os.getenv("LOG_FILE", "").strip()
FIRST_EPSS= os.getenv("FIRST_EPSS", "False").lower() in ("true", "1", "yes")

current_year = now.year
copyright_year = (
    f"2025–{current_year}" if current_year > 2025 else "2025"
)

footer_html = (
    f'<footer style="text-align:center; padding:1em 0; font-size:0.9em; color:#777;">'
    f'&copy; {copyright_year} '
    f'<a href="https://teams.microsoft.com/l/chat/0/0?users=julien.mousqueton@computacenter.com" target=_blank>Julien Mousqueton</a> – All rights reserved.<br>'
    'Sources : <a href="https://euvd.enisa.europa.eu/" target=_blank>ENISA</a> | <a href="https://www.first.org/" target=_blank>FIRST</a> <br><br>'
    '<a href="https://github.com/JMousqueton/EUVD-Alert" class="btn btn-dark btn-sm" target="_blank" style="margin-top:8px;">'
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-github" viewBox="0 0 16 16" style="margin-right:6px;">'
    '<path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 005.47 7.59c.4.07.55-.17.55-.38 '
    '0-.19-.01-.82-.01-1.49-2 .37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52 '
    '-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 '
    '0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.54 7.54 0 012-.27 7.54 '
    '7.54 0 012 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 '
    '0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 '
    '8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>'
    '</svg>'
    'View on GitHub'
    '</a>'
    '</footer>\n'
    '<!-- Matomo -->\n'
    '<script>\n'
    'var _paq = window._paq = window._paq || [];\n'
    '/* tracker methods like "setCustomDimension" should be called before "trackPageView" */\n'
    '_paq.push(["trackPageView"]);\n'
    '_paq.push(["enableLinkTracking"]);\n'
    '(function() {\n'
    '    var u="https://stats.mousqueton.io/";\n'
    '    _paq.push(["setTrackerUrl", u+"matomo.php"]);\n'
    '    _paq.push(["setSiteId", "4"]);\n'
    '    var d=document, g=d.createElement("script"), s=d.getElementsByTagName("script")[0];\n'
    '    g.async=true; g.src=u+"matomo.js"; s.parentNode.insertBefore(g,s);\n'
    '})();\n'
    '</script>\n'
    '<!-- End Matomo Code -->\n'
    )



legend_Radar = (
    '<div class="mt-4 p-3 bg-light border rounded">'
    '<h5><i class="fa-solid fa-circle-info"></i> CVSS Radar</h5>'
    '<ul class="small">'
    '<li><strong>AV</strong>: Attack Vector (Network, Adjacent, Local, Physical)</li>'
    '<li><strong>AC</strong>: Attack Complexity (Low, High)</li>'
    '<li><strong>PR</strong>: Privileges Required (None, Low, High)</li>'
    '<li><strong>UI</strong>: User Interaction (None, Required)</li>'
    '<li><strong>S</strong>: Scope (Unchanged, Changed)</li>'
    '<li><strong>C</strong>: Confidentiality Impact (None, Low, High)</li>'
    '<li><strong>I</strong>: Integrity Impact (None, Low, High)</li>'
    '<li><strong>A</strong>: Availability Impact (None, Low, High)</li>'
    '</ul></div>'
)

cvss_mapping = {
    "AV": {"N": 1.0, "A": 0.6, "L": 0.4, "P": 0.2},
    "AC": {"L": 1.0, "H": 0.5},
    "PR": {"N": 1.0, "L": 0.6, "H": 0.2},
    "UI": {"N": 1.0, "R": 0.5},
    "S": {"U": 0.5, "C": 1.0},
    "C": {"N": 0.0, "L": 0.5, "H": 1.0},
    "I": {"N": 0.0, "L": 0.5, "H": 1.0},
    "A": {"N": 0.0, "L": 0.5, "H": 1.0},
}

def cvss_severity_icon(score):
    try:
        score = float(score)
        if score == 0.0:
            return '<span title="Unknown">❓</span>'
        if score < 4.0:
            return '<span title="Low">🟢</span>'
        elif score < 7.0:
            return '<span title="Medium">🟡</span>'
        elif score < 9.0:
            return '<span title="High">🟠</span>'
        else:
            return '<span title="Critical">🔴</span>'
    except:
        return '<span title="N/A">❓</span>'


def epss_icon(epss_score: float):
    if epss_score >= 0.5:
        return "🔴"
    elif epss_score >= 0.1:
        return "🟡"
    else:
        return "🔵"

legend_EPSS = """
<div class="mt-4 p-3 bg-light border rounded">
  <h5><i class="fa-solid fa-circle-info"></i> CVSS risk</h5>
  <ul class="small mb-0">
    <li>{0} <strong>High</strong> (0.5 - 1)</li>
    <li>{1} <strong>Medium</strong> (0.1 - 0.49)</li>
    <li>{2} <strong>Low</strong> (0.0 – 0.09)</li>
  </ul>
  <div class="mt-3">
    <span class="badge bg-danger">EXPL</span> Exploited in the wild
</div>
</div>
""".format(
    epss_icon(1),
    epss_icon(0.2),
    epss_icon(0),
)

legend_CVSS = """
<div class="mt-4 p-3 bg-light border rounded">
  <h5><i class="fa-solid fa-circle-info"></i> CVSS Severity</h5>
  <ul class="small mb-0">
    <li>{0} <strong>Critical</strong> (9.0 – 10.0)</li>
    <li>{1} <strong>High</strong> (7.0 – 8.9)</li>
    <li>{2} <strong>Medium</strong> (4.0 – 6.9)</li>
    <li>{3} <strong>Low</strong> (0.1 – 3.9)</li>
    <li>{4} <strong>Unknown</strong> (0.0 or missing)</li>
  </ul>
</div>
""".format(
    cvss_severity_icon(9.5),
    cvss_severity_icon(8),
    cvss_severity_icon(5),
    cvss_severity_icon(2),
    cvss_severity_icon(0)
)


legend_text = """
    <div class="mt-4 p-3 bg-light shadow rounded">
        <ul class="small mb-0">
            <li><strong>CVSS</strong>: Common Vulnerability Scoring System</li>
            <li><strong>EPSS</strong>: Exploit Prediction Scoring System</li>
        </ul
    </div>
"""

def get_epss(cve_id):
    if FIRST_EPSS == "False":
        return 0,""
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "OK" and data.get("data"):
            epss = float(data["data"][0]["epss"])
            return epss_icon(epss), epss
        else:
            return "",0
    except Exception as e:
        logger.warning(f"⚠️ Failed to fetch EPSS for {cve_id}: {e}")
        #return "0.00"
        return "",0 

def remove_duplicates_preserve_order(seq):
    return list(dict.fromkeys(seq))

def send_html_email(subject, html_content, dry_run=False, high_priority=False,type="Alert"):
    smtp_server = os.getenv("MAIL_SMTP_SERVER")
    smtp_port = int(os.getenv("MAIL_SMTP_PORT", 25))
    mail_from = os.getenv("MAIL_FROM")
    mail_to = os.getenv("MAIL_TO")
    username = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")
    use_tls = os.getenv("MAIL_TLS", "False").lower() in ("true", "1", "yes")
    if dry_run:
        logger.info(f"\n--- DRY RUN: {subject} ---\n{html_content}\n")
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    if type == "Alert":
        msg["From"] = "Urgent " + mail_from
    elif type == "Daily":
        msg["From"] = "Daily " + mail_from
    elif type == "Monthly":
        msg["From"] = "Monthly " + mail_from
    else:
        msg["From"] = mail_from
    
    recipients = [email.strip() for email in mail_to.split(",") if email.strip()]
    if not recipients:
        logger.warning("❌ MAIL_TO is empty. Skipping email send.")
        return
    msg["To"] = ", ".join(recipients)
    if high_priority:
        msg["X-Priority"] = "1"
        msg["Priority"] = "urgent"
        msg["Importance"] = "high"
    msg.attach(MIMEText(html_content, "html"))
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(mail_from, recipients, msg.as_string())
        logger.info(f"✅ Email {subject} sent to {recipients}")
    except Exception as e:
        logger.info(f"❌ Failed to send email: {e}")

def generate_inline_noinfo_svg():
    return """
    <svg width="150" height="150" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f8f9fa"/>
      <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle"
            font-family="Arial" font-size="16" fill="#999">
        No Info
      </text>
    </svg>
    """

def generate_summary_card(vulns,vendor_line,type:"daily"):
    severity_counts = {"?": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    vendor_counts = defaultdict(int)
    nb_vulns = len(vulns)
    for v in vulns:
        score = v.get("baseScore")
        try:
            score = float(score)
        except:
            score = 0.0
        if score == 0.0:
            severity_counts["?"] += 1
        elif score < 4.0:
            severity_counts["low"] += 1
        elif score < 7.0:
            severity_counts["medium"] += 1
        elif score < 9.0:
            severity_counts["high"] += 1
        else:
            severity_counts["critical"] += 1
        for vendor_info in v.get("enisaIdVendor", []):
            name = vendor_info.get("vendor", {}).get("name", "").strip()
            if name:
                #vendors.add(name)
                vendor_counts[name] += 1
    
    # Format vendor list with counts
    vendor_list = ', '.join(
    f"{vendor.capitalize()} ({count})"
    for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[0].capitalize())
    )
    if type == "monthly":
        first_day_of_this_month = now_local.replace(day=1)
        last_month = first_day_of_this_month - timedelta(days=1)
        today = f"{last_month.strftime("%Y-%m")}-pie"

    return f"""
    <div class="card border-primary mb-3">
        <div class="card-header bg-primary text-white"><strong>🔎 &nbsp;Summary:</strong> {nb_vulns} vulnerabilities</div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-8">
                    <p class="card-text mb-2">
                        <strong>Severity breakdown:</strong><br>
                        <span title="Critical">{cvss_severity_icon(9.5)} {severity_counts['critical']}</span> &nbsp;
                        <span title="High">{cvss_severity_icon(8)} {severity_counts['high']}</span> &nbsp;
                        <span title="Medium">{cvss_severity_icon(5)} {severity_counts['medium']}</span> &nbsp;
                        <span title="Low">{cvss_severity_icon(2)} {severity_counts['low']}</span> &nbsp;
                        <span title="Unknown">{cvss_severity_icon(0)} {severity_counts['?']}</span>             
                    </p>
                    <p></BR></p>
                    <p class="card-text mb-2">
                        <strong>Filtered vendors:</strong><br> {vendor_line}
                    </p>
                    <p class="card-text mb-0">
                        <strong>Vendors with vulnerabilities:</strong><br> {vendor_list}
                    </p>
                </div>
                <div class="col-md-4 text-end">
                    <img src="https://vuln.mousqueton.io/{type}/{today}.png"
                        alt="Severity Breakdown Pie Chart"
                        class="img-fluid rounded shadow-sm"
                        style="max-width: 250px;">
                </div>
            </div>
        </div>
    </div>

    """

def categorize_severity(cvss):
    if cvss is None:
        return 'Unknown'
    elif cvss >= 9.0:
        return 'Critical'
    elif cvss >= 7.0:
        return 'High'
    elif cvss >= 4.0:
        return 'Medium'
    elif cvss > 0.0:
        return 'Low'
    else:
        return 'Unknown'

def generate_piechart(vulns, type="daily"):

    filtered = [v for v in vulns if v.get("baseScore") not in (None, 0)]
    if type == "daily":
        output_path = f"{DAILY_FOLDER}/{today}.png"
    else:
        output_path = f"{MONTHLY_FOLDER}/{type}-pie.png"
    # If nothing to show, exit early
    if not filtered:
        logger.warning("📊 No data to plot severity pie chart.")
        plt.figure(figsize=(6, 6))
        plt.text(0.5, 0.5, 'No Data', fontsize=20, ha='center', va='center')
        plt.axis('off')
        plt.savefig(output_path, bbox_inches='tight')
        plt.close()
        return output_path

        # Count severities
    severity_counts = Counter(categorize_severity(v["baseScore"]) for v in filtered)

    # Filter out zero values
    categories = []
    counts = []
    colors = []

    color_map = {
        'Critical': 'red',
        'High': 'orange',
        'Medium': 'yellow',
        'Low': 'green',
        'Unknown': 'grey'
    }
    
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            categories.append(severity)
            counts.append(count)
            colors.append(color_map[severity])

    # Plot the pie chart
    plt.figure(figsize=(6, 6))
    plt.pie(counts, labels=categories, colors=colors, autopct='%1.0f%%', startangle=140)
    plt.title('Severity Breakdown')
    plt.axis('equal')
    plt.savefig(output_path, transparent=True, bbox_inches='tight')
    plt.close()

    return output_path

def daily_report(vulns, vendor_line,title):
    html_path = f"./web/daily/{today}.html"
    # Format the date for the title
    full_title = f"{title} - {formatted_date}"
    rows = ""
    nb_vulns = len(vulns)
    for v in vulns:
        #generate_radar_chart(v.get("baseScoreVector", ""), v["id"])
        alt_id = v.get('aliases', '').strip()
        alias_list = v.get("aliases", "")
        match = re.search(r"CVE-\d{4}-\d{1,5}", alias_list)
        cve_alias = match.group(0) if match else ""
        score = v.get("baseScore", "N/A")
        icon = cvss_severity_icon(score)
        # exploited = "Yes" if v.get("exploited", False) else "No"
        exploited = v.get("exploited", False)
        desc = v.get("description", "")[:200].replace("\n", " ") + "..."
        #product = ", ".join(p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", []))
        product_names = [p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", [])]
        unique_product_names = remove_duplicates_preserve_order(product_names)
        product = ", ".join(unique_product_names)
        vendor = ", ".join(vn.get("vendor", {}).get("name", "n/a") for vn in v.get("enisaIdVendor", []))
        url = f"https://euvd.enisa.europa.eu/enisa/{v['id']}"
        vector = v.get("baseScoreVector", "")
        has_radar = bool(vector and "/" in vector)

        if has_radar:
            generate_radar_chart(vector, v["id"], score)
            img_tag = f'<img src="{RADAR_URL}/{v["id"]}.png" class="img-fluid rounded shadow-sm" style="max-width: 150px;" alt="Radar">'
        else:
            img_tag = generate_inline_noinfo_svg()
        epss_emoji, epss_value = get_epss(cve_alias)
        rows += f"""
            <tr>
                <td><a href="{url}">{v['id']}</a><!-- <br><small>{alt_id}</small> --></td>
                <td data-sort="{score}">{icon} {score}</td>
        """
        if FIRST_EPSS:
            rows += f"""
                <td data_sort="{epss_value}"> &nbsp;&nbsp;{epss_emoji}
            """
            if exploited:
                rows += '<br><span class="badge bg-danger ms-1" title="Exploited in the wild">EXPL</span>'
            rows += '</td>'
        rows += f"""
                <!-- <td>{exploited}</td> --> 
                <td>{vendor}</td>
                <td>{product}</td>
                <td>{desc}</td>
                <td>{img_tag}</td>
            </tr>
        """
    report_url = f"{DAILY_URL}/{today}.html"
    generate_piechart(vulns)
    html_content = f"""
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="icon" type="image/png" href="https://vuln.mousqueton.io/favicon.png">
                <link rel="shortcut icon" href="https://vuln.mousqueton.io/favicon.ico">
                <!-- Open Graph Meta -->
                <meta property="og:type" content="article">
                <meta property="og:locale" content="en_US">
                <meta property="og:title" content="Daily Vulnerability Vendors Report - {formatted_date}">
                <meta property="og:description" content="Daily breakdown of {nb_vulns} vulnerabilities affecting these vendors {vendor_line}.">
                <meta property="og:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta property="og:url" content="https://vuln.mousqueton.io/daily/{today}.html">
                <meta property="og:site_name" content="Julien Mousqueton">

                <!-- Twitter Card Meta -->
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:title" content="Daily Vulnerability Vendors Report - {formatted_date}">
                <meta name="twitter:description" content="{nb_vulns} new vulnerabilities across {vendor_line}.">
                <meta name="twitter:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta name="twitter:site" content="@JMousqueton">
                <meta name="twitter:creator" content="@JMousqueton">
                <meta name="twitter:url" content="https://vuln.mousqueton.io/daily/{today}.html">
                <title>{full_title}</title>
                <!-- Bootstrap 5.3.3 -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

                <!-- Font Awesome 6.5.0 -->
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">

                <!-- DataTables + Bootstrap 5 -->
                <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

                <!-- Buttons (Bootstrap 5 style only) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.bootstrap5.min.css">

                <!-- Responsive (Bootstrap 5 style) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/responsive/3.0.4/css/responsive.bootstrap5.min.css">

                <!-- jQuery 3.7.1 -->
                <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

                <!-- DataTables core + Bootstrap 5 -->
                <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
                <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>

                <!-- Buttons (copy + CSV only) -->
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.bootstrap5.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>

                <!-- Responsive -->
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/dataTables.responsive.min.js"></script>
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/responsive.bootstrap5.min.js"></script>

                <!-- Dependencies for Excel -->
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

                <style>
                    table {{
                        border-collapse: collapse;
                        width: 100%;
                        font-family: Arial, sans-serif;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        vertical-align: top;
                    }}
                    th {{
                        background-color: #f2f2f2;
                        text-align: left;
                    }}
                    tr:hover {{background-color: #f5f5f5;}}


                    .fa-icon::before {{
                        content: attr(data-fallback);
                        display: inline-block;
                    }}

                    .fa-icon.fas::before,
                    .fa-icon.fa-solid::before {{
                        content: "";
                    }}
                    
                </style>
            </head>
            <body>
                <div class="container mt-4">
                    <h2><i class="fa-regular fa-calendar-days"></i> {full_title}</h2>
                    <p>📄 <a href="{report_url}">View this report online</a></p>
                    <br>
                    {generate_summary_card(vulns,vendor_line,"daily")}
                    <div style="text-align:center; font-size:0.8em; color:#777; padding-top:1em;">
                        Page generated on {full_date}
                    </div>
                    <table id="vuln-table" class="table table-bordered table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>ID</th>
                                <th>CVSS</th>
    """
    if FIRST_EPSS:
        html_content += f"""
                <th>EPSS</th>
        """
    html_content += f"""
                                <!-- <th>Exploited</th> --> 
                                <th>Vendor</th>
                                <th data-sort-method="none">Product</th>
                                <th data-sort-method="none">Description</th>
                                <th data-sort-method="none">Radar</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                    <script>
                        $(document).ready(function () {{
                            $('#vuln-table').DataTable({{
                            pageLength: 25,
                            lengthMenu: [10, 25, 50, 100],
                            order: [],
                            responsive: true,
                            dom: 'Bfrtip',
                            buttons: ['excel'],
                            columnDefs: [
    """
    if FIRST_EPSS:
        html_content += f"""
                                {{ orderable: false, targets: [4, 5, 6] }}  // Disable Product, Description, and Radar
        """
    else:
        html_content += f"""
                                {{ orderable: false, targets: [4, 5] }}  // Disable Product and Description
        """
    html_content += f"""
                            ]
                            }});
                        }});
                    </script>
                    <div class="mt-4 p-3 bg-light border rounded">
                        <strong>Legend:</strong>
                        <div class="row">
                            <div class="col-md-4">
                                {legend_Radar}
                            </div>
                            <div class="col-md-4">
                                {legend_CVSS}
                            </div>
                            <div class="col-md-4">
                                {legend_EPSS}
                            </div>    
                        </div>
                        <strong>Definition:</strong>
                    {legend_text}
                    <p></p>
                    </div>  </div> 
                {footer_html}
            </body>
        </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_content, html_path

def load_json_file(path):
    if not os.path.exists(path):
        logger.error(f"❌ File not found: {path}")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"❌ File does not contain a valid list: {path}")
                return []
            return data
    except json.JSONDecodeError as e:
        logger.error(f"❌ JSON decode error in {path}: {e}")
        return []
    except Exception as e:
        logger.exception(f"❌ Unexpected error reading {path}: {e}")
        return []

"""
def matches_keyword(entry, keywords):
    vendor_names = " ".join(
        vn.get("vendor", {}).get("name", "") for vn in entry.get("enisaIdVendor", [])
    ).lower()
    positive = [k.lower() for k in keywords if not k.startswith("!")]
    negative = [k[1:].lower() for k in keywords if k.startswith("!")]
    if any(exclude in vendor_names for exclude in negative):
        return False
    return any(keyword in vendor_names for keyword in positive)

def matches_keyword_all(entry, keywords):
    text = (entry.get("id", "") + " " + entry.get("description", "") + " " + entry.get("aliases", "")).lower()
    positive = [k.lower() for k in keywords if not k.startswith("!")]
    negative = [k[1:].lower() for k in keywords if k.startswith("!")]
    if any(exclude in text for exclude in negative):
        return False
    return any(keyword in text for keyword in positive)
"""

def matches_keyword(entry, keywords):
    """
    Checks if an entry matches the provided filters based on a manufacturer-product
    logic derived from the keywords list. For Manufacturer:Product filters,
    a match occurs if the manufacturer matches AND any of the specified products
    for that manufacturer match the entry's products. Returns 0 if not matched, 1 if matched.
    Args:
        entry: The entry data structure.
        keywords: A list of strings defining the filters.
                  Format: "Manufacturer", "Manufacturer:Product",
                          "!Manufacturer", "!Manufacturer:Product"
    Returns:
        1 if the entry matches at least one positive filter derived from
        keywords and none of the negative filters derived from keywords.
        0 otherwise.
    """
    # --- Extract and normalize vendor and product names from the entry ---
    product_names_lower = " ".join([
        item.get('product', {}).get('name', '')
        for item in entry.get("enisaIdProduct", []) if item
    ]).lower()

    vendor_names_lower = ", ".join([
        vn.get("vendor", {}).get("name", "")
        for vn in entry.get("enisaIdVendor", []) if vn
    ]).lower()

    # --- Parse keywords to build the filter structures ---
    # Positive filters
    positive_manufacturer_only_filters = set() # Manufacturers where any product matches
    positive_manufacturer_product_filters = {} # {manufacturer: [product1, product2, ...]} for specific products

    # Negative filters
    negative_manufacturers = set() # Manufacturers to exclude entirely
    negative_manufacturer_products_set = set() # {(manufacturer, product), ...} specific combos to exclude

    for filter_str in keywords:
        if not isinstance(filter_str, str):
             continue

        filter_str = filter_str.strip()
        if not filter_str:
            continue

        is_negative = filter_str.startswith("!")
        if is_negative:
            filter_str = filter_str[1:].strip()
            if not filter_str:
                 continue

        parts = filter_str.split(":", 1)
        manufacturer = parts[0].strip()

        if not manufacturer:
            continue

        if len(parts) == 2:
            # Manufacturer:Product filter
            product = parts[1].strip()
            if not product:
                # Manufacturer only (ends with ':') - Treat as Manufacturer-only filter type
                if is_negative:
                    negative_manufacturers.add(manufacturer.lower()) # Store negative manufacturers lowercase
                else:
                    positive_manufacturer_only_filters.add(manufacturer.lower()) # Store positive any-product manufacturers lowercase
            else:
                # Valid Manufacturer:Product filter
                if is_negative:
                    negative_manufacturer_products_set.add((manufacturer.lower(), product.lower())) # Store negative combos lowercase
                else:
                    # Store positive manufacturer-product filters. Use lower case for keys/values here
                    positive_manufacturer_product_filters.setdefault(manufacturer.lower(), []).append(product.lower())
        else:
            # Manufacturer-only filter (no ':')
            if is_negative:
                negative_manufacturers.add(manufacturer.lower()) # Store negative manufacturers lowercase
            else:
                positive_manufacturer_only_filters.add(manufacturer.lower()) # Store positive any-product manufacturers lowercase

    # --- Apply Negative Filters ---

    # Negative Manufacturers: Check if any excluded manufacturer is in the entry's vendor names
    for nm_lower in negative_manufacturers:
        if nm_lower in vendor_names_lower:
            return 0 # Excluded by manufacturer

    # Negative Manufacturer-Product Pairs: Check if any excluded combo is in the entry
    for nmp_mf_lower, nmp_prod_lower in negative_manufacturer_products_set:
        if nmp_mf_lower in vendor_names_lower and nmp_prod_lower in product_names_lower:
             return 0 # Excluded by manufacturer:product combo

    # --- Apply Positive Filters ---

    # 1. Check Positive Manufacturer-Only Filters (match any product)
    for pm_lower in positive_manufacturer_only_filters:
        if pm_lower in vendor_names_lower:
            return 1 # Matched a manufacturer requesting any product

    # 2. Check Positive Manufacturer-Product Filters (match at least one specified product)
    for pmp_mf_lower, required_products_lower_list in positive_manufacturer_product_filters.items():
        if pmp_mf_lower in vendor_names_lower:
            # Manufacturer matches, now check if ANY of the required products match
            for required_prod_lower in required_products_lower_list:
                if required_prod_lower in product_names_lower:
                    return 1 # Matched manufacturer AND one of the specified products

    # --- If no positive filter matched after checking all ---
    return 0 # No match found




def filter_vulns(vulnerabilities, keywords, severity_filter=False):
    matches = []
    for v in vulnerabilities:
        vuln_id = v.get("id", "UNKNOWN")
        vendor_names = [vn.get("vendor", {}).get("name", "").strip().lower() for vn in v.get("enisaIdVendor", [])]
        vendor_is_na = all(name in ("", "n/a") for name in vendor_names)

        matched_keyword = None
        match = False

        if vendor_is_na:
            # Fallback: match in description, id or aliases
            text = (
                v.get("id", "") + " " +
                v.get("description", "") + " " +
                v.get("aliases", "")
            ).lower()
            logger.debug(f"[{vuln_id}] TEXT for keyword matching: {text}")

            positive = [k for k in keywords if not k.startswith("!")]
            negative = [k[1:].lower() for k in keywords if k.startswith("!")]

            if any(neg in text for neg in negative):
                match = False
                logger.debug(f"[{vuln_id}] Skipped due to negative keyword match.")
            else:
                for keyword in positive:
                    if keyword.lower() in text:
                        matched_keyword = keyword[0].upper() + keyword[1:]  # Uppercase first letter
                        match = True
                        logger.debug(f"[{vuln_id}] Match found with keyword '{matched_keyword}' in fallback text.")
                        break

            if match and matched_keyword:
                v["enisaIdVendor"] = [{
                    "vendor": {"name": matched_keyword}
                }]
        else:
            match = matches_keyword(v, keywords)
            logger.debug(f"[{vuln_id}] Vendor(s): {vendor_names} → Match: {match}")

        if match:
            try:
                if severity_filter:
                    score = float(v.get("baseScore", 0))
                    if score >= MIN_CVSS_TO_ALERT:
                        logger.debug(f"[{vuln_id}] Score {score} >= threshold {MIN_CVSS_TO_ALERT} → Added to matches")
                        matches.append(v)
                    else:
                        logger.debug(f"[{vuln_id}] Score {score} < threshold {MIN_CVSS_TO_ALERT} → Skipped")
                else:
                    matches.append(v)
                    logger.debug(f"[{vuln_id}] Match added (no severity filter).")
            except ValueError:
                logger.debug(f"[{vuln_id}] Invalid CVSS score → Skipped")
    return matches



def filter_last_month(vulns):
    first_day_this_month = datetime(now.year, now.month, 1)
    last_month_end = first_day_this_month - timedelta(days=1)
    last_month_start = datetime(last_month_end.year, last_month_end.month, 1)
    filtered = []

    for v in vulns:
        date_str = v.get("dateUpdated", "")
        try:
            date = datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p")
            if last_month_start <= date <= last_month_end:
                filtered.append(v)
        except ValueError:
            continue  # Skip invalid dates silently
    return filtered

def load_sent_ids(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            return set(json.load(f))
        except json.JSONDecodeError:
            return set()

def save_sent_ids(filepath, sent_ids):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sorted(list(sent_ids)), f, indent=2)

def parse_cvss_vector(vector):
    try:
        parts = vector.split('/')
        scores = []
        labels = []
        for part in parts[1:]:
            metric, value = part.split(':')
            if metric in cvss_mapping:
                score = cvss_mapping[metric].get(value, 0.0)
                scores.append(score)
                labels.append(metric)
        return labels, scores
    except:
        return [], []

def generate_radar_chart(cvss_vector, chart_id, score=None):
    labels, values = parse_cvss_vector(cvss_vector)
    if not labels or not values:
        return None

    values += values[:1]
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    angles += angles[:1]

    color = get_cvss_color(score)

    fig, ax = plt.subplots(figsize=(3, 3), subplot_kw=dict(polar=True))
    ax.plot(angles, values, linewidth=2, color=color)
    ax.fill(angles, values, alpha=0.25, color=color)
    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels)
    ax.set_title("CVSS Radar", size=10)

    # Score CVSS au centre
    if score is not None:
        try:
            score_float = float(score)
            ax.text(0.5 * np.pi, 0, f"{score_float:.1f}",
                    ha='center', va='center', fontsize=12, fontweight='bold',
                    bbox=dict(facecolor='white', edgecolor='gray', boxstyle='round,pad=0.3'))
        except ValueError:
            pass

    Path(RADAR_FOLDER).mkdir(parents=True, exist_ok=True)
    path = f"{RADAR_FOLDER}/{chart_id}.png"
    plt.tight_layout()
    plt.savefig(path, format='png')
    plt.close()
    return path

def get_cvss_color(score):
    try:
        score = float(score)
        if score == 0.0:
            return "#999999"  # gris pour inconnu
        elif score < 4.0:
            return "#28a745"  # vert
        elif score < 7.0:
            return "#ffc107"  # jaune
        elif score < 9.0:
            return "#fd7e14"  # orange
        else:
            return "#dc3545"  # rouge
    except:
        return "#999999"  # par défaut


def alert(vulns, vendor_line, title):
    full_title = f"{title} - {formatted_date}"
    rows = ""
    vendor_counter = Counter()
    for v in vulns:
        alt_id = v.get('aliases', '').strip()
        alias_list = v.get("aliases", "")
        match = re.search(r"CVE-\d{4}-\d{1,5}", alias_list)
        cve_alias = match.group(0) if match else ""
        score = v.get("baseScore", "N/A")
        icon = cvss_severity_icon(score)

        exploited = v.get("exploited", False)
        desc = v.get("description", "")[:200].replace("\n", " ") + "..."
        product_names = [p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", [])]
        unique_product_names = remove_duplicates_preserve_order(product_names)
        product = ", ".join(unique_product_names)
        vendor = ", ".join(vn.get("vendor", {}).get("name", "n/a") for vn in v.get("enisaIdVendor", []))
        url = f"https://euvd.enisa.europa.eu/enisa/{v['id']}"
        vector = v.get("baseScoreVector", "")
        has_radar = bool(vector and "/" in vector)
        epss_emoji, epss_value = get_epss(cve_alias)

        for vn in v.get("enisaIdVendor", []):
            vendor_name = vn.get("vendor", {}).get("name", "").strip()
            if vendor_name:
                vendor_counter[vendor_name] += 1

        if has_radar:
            generate_radar_chart(vector, v["id"], score)
            img_tag = f'<img src="{RADAR_URL}/{v["id"]}.png" class="img-fluid rounded shadow-sm" style="max-width: 150px;" alt="Radar">'
        else:
            img_tag = generate_inline_noinfo_svg()
        rows += f"""
            <tr>
                <td><a href="{url}">{v['id']}</a><br><small>{v.get("aliases", "")}</small></td>
                <td data_sort="{score}">{icon} {score}</td>
        """
        if FIRST_EPSS:
            rows += f"""
                <td data_sort="{epss_value}">{epss_emoji}
            """
            if exploited:
                rows += '<br><span class="badge bg-danger ms-1" title="Exploited in the wild">EXPL</span>'
            rows += '</td>'
        rows += f"""
                <td>{vendor}</td>
                <td>{product}</td>
                <td>{desc}</td>
                <td>{img_tag}</td>
            </tr>
        """

    match_vendor_line = ", ".join(f"{vendor} ({count})" for vendor, count in sorted(vendor_counter.items()))

    timestamp = now_local.strftime("%Y-%m-%d-%H-%M")
    report_url = f"{ALERTS_URL}/{timestamp}.html"    
    html_content = f"""
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="icon" type="image/png" href="https://vuln.mousqueton.io/favicon.png">
                <link rel="shortcut icon" href="https://vuln.mousqueton.io/favicon.ico">
                <!-- Open Graph Meta -->
                <meta property="og:type" content="article">
                <meta property="og:locale" content="en_US">
                <meta property="og:title" content="Real-time Vulnerability Alert - {timestamp}">
                <meta property="og:description" content="Real-time Vulnerability Alert based on {vendor_line}.">
                <meta property="og:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta property="og:url" content="https://vuln.mousqueton.io/alerts/{timestamp}.html">
                <meta property="og:site_name" content="Julien Mousqueton">

                <!-- Twitter Card Meta -->
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:title" content="Real-time Vulnerability Alert - {timestamp}">
                <meta name="twitter:description" content="Real-time Vulnerability Alert based on {vendor_line}.">
                <meta name="twitter:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta name="twitter:site" content="@JMousqueton">
                <meta name="twitter:creator" content="@JMousqueton">
                <meta name="twitter:url" content="https://vuln.mousqueton.io/alerts/{timestamp}.html">
                <title>🚨 Real-time Vulnerability Alert – {timestamp}</title>
                <!-- Bootstrap 5.3.3 -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

                <!-- Font Awesome 6.5.0 -->
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">

                <!-- DataTables + Bootstrap 5 -->
                <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

                <!-- Buttons (Bootstrap 5 style only) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.bootstrap5.min.css">

                <!-- Responsive (Bootstrap 5 style) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/responsive/3.0.4/css/responsive.bootstrap5.min.css">

                <!-- jQuery 3.7.1 -->
                <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

                <!-- DataTables core + Bootstrap 5 -->
                <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
                <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>

                <!-- Buttons (copy + CSV only) -->
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.bootstrap5.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>

                <!-- Responsive -->
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/dataTables.responsive.min.js"></script>
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/responsive.bootstrap5.min.js"></script>

                <!-- Dependencies for Excel -->
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

                <style>
                    table {{
                        border-collapse: collapse;
                        width: 100%;
                        font-family: Arial, sans-serif;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        vertical-align: top;
                    }}
                    th {{
                        background-color: #f2f2f2;
                        text-align: left;
                    }}
                    tr:hover {{background-color: #f5f5f5;}}


                    .fa-icon::before {{
                        content: attr(data-fallback);
                        display: inline-block;
                    }}

                    .fa-icon.fas::before,
                    .fa-icon.fa-solid::before {{
                        content: "";
                    }}
                </style>
            </head>
        <body>
            <div class="container mt-4">
                <h2 class="text-danger">🚨 {full_title}</h2>
                <p>📄 <a href="{report_url}">View this report online</a></p>
                <br>
                <div class="card border-primary mb-3">
                    <div class="card-header bg-primary text-white"><strong>🔎 &nbsp;Information</strong></div>
                        <div class="card-body">
                            <p><strong>This is an automated alert for critical vulnerabilities.</strong></p>
                            <p><strong>Minimum CVSS score: </strong><span class="badge bg-danger">{MIN_CVSS_TO_ALERT}</span></p>
                            <p><strong>Filtered vendors: </strong>{vendor_line}</p>
                            <p><strong>Matched vendors: </strong>{match_vendor_line}</p>
                        </div>
                    </div>
              
                <table id="vuln-table" class="table table-bordered table-hover align-middle">
                    <thead class="table-danger">
                        <tr>
                            <th>ID</th>
                            <th>CVSS</th>
        """
    if FIRST_EPSS:
        html_content += f"""
                            <th>EPSS</th>
        """
    html_content += f"""
                            <th>Vendor</th>
                            <th>Product</th>
                            <th>Description</th>
                            <th>Radar</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
                <script>
                        $(document).ready(function () {{
                            $('#vuln-table').DataTable({{
                            pageLength: 25,
                            lengthMenu: [10, 25, 50, 100],
                            order: [],
                            responsive: true,
                            dom: 'Bfrtip',
                            buttons: ['excel'],
                            columnDefs: [
    """
    if FIRST_EPSS:
        html_content += f"""
                                {{ orderable: false, targets: [4, 5, 6] }}  // Disable Product, Description, and Radar
        """
    else:
        html_content += f"""
                                {{ orderable: false, targets: [4, 5] }}  // Disable Product and Description
        """
    html_content += f"""
                            ]
                            }});
                        }});
                    </script>
                <div class="mt-4 p-3 bg-light border rounded">
                        <strong>Legend:</strong>
                        <div class="row">
                            <div class="col-md-4">
                                {legend_Radar}
                            </div>
                            <div class="col-md-4">
                                {legend_CVSS}
                            </div>
                            <div class="col-md-4">
                                {legend_EPSS}
                            </div>    
                        </div>
                        <strong>Definition:</strong>
                    {legend_text}
                    <p></p>
                    </div>  </div>
                    {footer_html}
                </div>
            </body>
        </html>
    """
    # Save the HTML content to ./web/alert/
    alert_path = f"{ALERTS_FOLDER}/{timestamp}.html"
    os.makedirs(os.path.dirname(alert_path), exist_ok=True)
    with open(alert_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"📁 Alert HTML page saved to {alert_path}")
    return html_content

def generate_vuln_bar_chart(vulns, month_year, output_dir=MONTHLY_FOLDER):
    # Define severity levels and color map
    severity_levels = ["critical", "high", "medium", "low", "?"]
    color_map = {
        "critical": "red",
        "high": "orange",
        "medium": "gold",
        "low": "green",
        "?": "gray"
    }

    def get_severity(score):
        try:
            score = float(score)
        except:
            score = 0.0
        if score == 0.0:
            return "?"
        elif score < 4.0:
            return "low"
        elif score < 7.0:
            return "medium"
        elif score < 9.0:
            return "high"
        else:
            return "critical"

    # Parse the month and year
    target_date = datetime.strptime(month_year, "%Y-%m")
    month_year_str = target_date.strftime("%B %Y")
    target_month = target_date.month
    target_year = target_date.year

    # Setup date range
    first_day = datetime(target_year, target_month, 1).date()
    if target_month == 12:
        last_day = datetime(target_year + 1, 1, 1).date() - timedelta(days=1)
    else:
        last_day = datetime(target_year, target_month + 1, 1).date() - timedelta(days=1)
    all_days = [first_day + timedelta(days=i) for i in range((last_day - first_day).days + 1)]

    # Count vulnerabilities per severity per day
    daily_counts = defaultdict(lambda: defaultdict(int))
    for v in vulns:
        try:
            pub_date = datetime.strptime(v["dateUpdated"], "%b %d, %Y, %I:%M:%S %p").date()
            if pub_date.year == target_year and pub_date.month == target_month:
                severity = get_severity(v.get("baseScore", 0.0))
                daily_counts[pub_date][severity] += 1
        except Exception:
            continue

    # Prepare data for plotting
    severity_data = {sev: [daily_counts[day][sev] for day in all_days] for sev in severity_levels}

    # Plotting
    fig, ax = plt.subplots(figsize=(14, 6))
    bottom = [0] * len(all_days)

    for sev in severity_levels:
        ax.bar(all_days, severity_data[sev], bottom=bottom, color=color_map[sev], label=sev.capitalize())
        bottom = [bottom[i] + severity_data[sev][i] for i in range(len(all_days))]

    ax.set_title(f"Cumulative vulnerabilities per day for selected vendors in {month_year_str}", fontsize=14)
    ax.set_xlabel("Date\n(c) Julien Mousqueton")
    ax.set_ylabel("Number of vulnerabilities")
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    ax.yaxis.grid(True, linestyle='--', linewidth=0.5, color='lightgray')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%d-%b'))
    plt.xticks(rotation=45)
    ax.legend(title="Severity")

    # Save figure
    filename = f"{month_year}.png"
    output_path = os.path.join(output_dir, filename)
    fig.tight_layout()
    plt.savefig(output_path, dpi=100)
    plt.close()

    return output_path

def monthly_summary(vulns, keywords, month_year):
    parsed_date = datetime.strptime(month_year, "%B %Y")
    month_year_filename = parsed_date.strftime("%Y-%m")
    generate_vuln_bar_chart(vulns,month_year_filename)
    severity_levels = ["critical", "high", "medium", "low", "?"]
    vendor_severity = {k: {s: 0 for s in severity_levels} for k in sorted(keywords)}
    nb_vulns = len(vulns)
    for v in vulns:
        vendor_names = [vn.get("vendor", {}).get("name", "").strip() for vn in v.get("enisaIdVendor", [])]
        try:
            score = float(v.get("baseScore", 0))
        except:
            score = 0.0
        if score == 0.0:
            severity = "?"
        elif score < 4.0:
            severity = "low"
        elif score < 7.0:
            severity = "medium"
        elif score < 9.0:
            severity = "high"
        else:
            severity = "critical"

        for vendor in vendor_names:
            for keyword in keywords:
                if keyword.lower() in vendor.lower():
                    vendor_severity[keyword][severity] += 1
    rows = ""
    for vendor, counts in vendor_severity.items():
        total = sum(counts.values())
        if total == 0:
            rows += f"<tr><th class='text-muted' style='text-decoration: line-through;'>{vendor}</th>"
        else:
            rows += f"<tr><th>{vendor}</th>"
        for sev in severity_levels:
            if counts[sev] != 0:
                rows += f'<td data-sort="{counts[sev]}"><strong>{counts[sev]}</strong></td>'
            else:
                rows += f'<td data-sort="0">0</td>'
        rows += "</tr>"
    month_id = datetime.strptime(month_year, "%B %Y").strftime("%Y-%m")
    html_path = f"{MONTHLY_FOLDER}/{month_id}.html"
    report_url = f"{MONTHLY_URL}/{month_id}.html"

    ###vendor_line = ", ".join(sorted(keywords))
    # Filter and extract vendor names
    vendor_names = {
            entry.split(":")[0].strip()
            for entry in keywords
            if not entry.startswith("!")
    }

    # Sort and join
    vendor_line = ", ".join(sorted(vendor_names))

    generate_piechart(vulns,month_id)
    html_content = f"""
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="icon" type="image/png" href="https://vuln.mousqueton.io/favicon.png">
                <link rel="shortcut icon" href="https://vuln.mousqueton.io/favicon.ico">
                <!-- Open Graph Meta -->
                <meta property="og:type" content="article">
                <meta property="og:locale" content="en_US">
                <meta property="og:title" content="Monthly Vulnerability Vendors Summarize - {month_year}">
                <meta property="og:description" content="Monthly breakdown of {nb_vulns} vulnerabilities affecting these vendors {vendor_line}.">
                <meta property="og:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta property="og:url" content="https://vuln.mousqueton.io/monthly/{month_id}.html">
                <meta property="og:site_name" content="Julien Mousqueton">

                <!-- Twitter Card Meta -->
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:title" content="Monthly Vulnerability Vendors Summarize - {month_year}">
                <meta name="twitter:description" content="In {month_year}, {nb_vulns} new vulnerabilities across {vendor_line}.">
                <meta name="twitter:image" content="https://vuln.mousqueton.io/assets/daily-preview.png">
                <meta name="twitter:site" content="@JMousqueton">
                <meta name="twitter:creator" content="@JMousqueton">
                <meta name="twitter:url" content="https://vuln.mousqueton.io/monthly/{month_id}.html">
                <title>Monthly Vulnerability Summary – {month_year}</title>
                <!-- Bootstrap 5.3.3 -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

                <!-- Font Awesome 6.5.0 -->
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">

                <!-- DataTables + Bootstrap 5 -->
                <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

                <!-- Buttons (Bootstrap 5 style only) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.bootstrap5.min.css">

                <!-- Responsive (Bootstrap 5 style) -->
                <link rel="stylesheet" href="https://cdn.datatables.net/responsive/3.0.4/css/responsive.bootstrap5.min.css">

                <!-- jQuery 3.7.1 -->
                <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

                <!-- DataTables core + Bootstrap 5 -->
                <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
                <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>

                <!-- Buttons (copy + CSV only) -->
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.bootstrap5.min.js"></script>
                <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>

                <!-- Responsive -->
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/dataTables.responsive.min.js"></script>
                <script src="https://cdn.datatables.net/responsive/3.0.4/js/responsive.bootstrap5.min.js"></script>

                <!-- Dependencies for Excel -->
                <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

                <style>
                    table {{
                        border-collapse: collapse;
                        width: 100%;
                        font-family: Arial, sans-serif;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        vertical-align: top;
                    }}
                    th {{
                        background-color: #f2f2f2;
                        text-align: left;
                    }}
                    tr:hover {{background-color: #f5f5f5;}}


                    .fa-icon::before {{
                        content: attr(data-fallback);
                        display: inline-block;
                    }}

                    .fa-icon.fas::before,
                    .fa-icon.fa-solid::before {{
                        content: "";
                    }}
                </style>
            </head>
        <body>
            <div class="container mt-4">
                <h2>📊 Monthly Vulnerability Summary – {month_year}</h2>
                <p>📄 <a href="{report_url}">View this report online</a></p>
                <br>
                {generate_summary_card(vulns,vendor_line,type="monthly")}
                <br>
                <p>Summary of vulnerabilities by vendor and severity level.</p>
                <table id="vuln-table" class="table table-bordered table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>Vendor</th>
                            <th data-sort-method="custom-number">{cvss_severity_icon(9.5)}</th>
                            <th data-sort-method="custom-number">{cvss_severity_icon(8)}</i></th>
                            <th data-sort-method="custom-number">{cvss_severity_icon(5)}</i></th>
                            <th data-sort-method="custom-number">{cvss_severity_icon(2)}</th>
                            <th data-sort-method="custom-number">{cvss_severity_icon(0)}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
                <script>
                    $(document).ready(function () {{
                        $('#vuln-table').DataTable({{
                        pageLength: 25,
                        lengthMenu: [10, 25, 50, 100],
                        order: [],
                        responsive: true,
                        dom: 'Bfrtip',
                        buttons: ['excel'],
                        columnDefs: [
                            {{ orderable: false, targets: -1 }}  // désactive le tri sur la colonne "? (inconnu)"
                        ]
                        }});
                    }});
                </script>
                <div class="text-center my-4">
    
    <img src="{MONTHLY_URL}/{month_id}.png" alt="Cumulative Vulnerabilities per Day for selected vendors for {month_year}" class="img-fluid rounded shadow">
</div>
                {legend_CVSS}
            </div>
            {footer_html}
            </body>
        </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_content, html_path

def list_vendors():
    try:
        with open(VULN_FILE, 'r', encoding='utf-8') as file:
            data = json.load(file)
        i = 0
        vendors = set()
        for entry in data:
            for vendor_entry in entry.get("enisaIdVendor", []):
                name = vendor_entry.get("vendor", {}).get("name", "").strip()
                if name and name.lower() != "n/a":
                    vendors.add(name)

        sorted_vendors = sorted(vendors)

        logger.info("Unique vendors found (sorted alphabetically):")
        for vendor in sorted_vendors:
            print(f"{vendor}")
            i+=1
        print(f"Total unique vendors: {i}")
    except FileNotFoundError:
        logger.error(f"File '{VULN_FILE}' not found.")
    except json.JSONDecodeError:
        logger.error(f"File '{VULN_FILE}' is not valid JSON.")
    except Exception as e:
        logger.exception(f"Unexpected error while listing vendors: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--daily", "-D", action="store_true", help="Send daily report")
    parser.add_argument("--alert", "-A", action="store_true", help="Send alert report")
    parser.add_argument("--monthly", "-M", action="store_true", help="Send monthly summary")
    parser.add_argument("--dry-run", action="store_true", help="Simulate sending without actually sending emails")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")  
    parser.add_argument("--log", action="store_true", help="Enable logging to file if LOG_FILE is set in .env")  
    parser.add_argument('--list', '-L', action='store_true', help='List all unique vendors alphabetically from eucv.json')
    args = parser.parse_args()

    if args.log and LOG_FILE_PATH:
        file_handler = logging.FileHandler(LOG_FILE_PATH)
        file_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info("-"*40)
        logger.info(f"🚀 Running script: {os.path.abspath(sys.argv[0])} with args: {' '.join(sys.argv[1:])}")
        logger.info(f"📂 File logging enabled: {LOG_FILE_PATH}")
    elif args.log:
        logger.warning("⚠️ --log flag used but LOG_FILE is not set in .env")


    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled.")

    if args.list:
        list_vendors()
        sys.exit(0)

    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logger.debug("🔒 Lock acquired successfully.")
    except BlockingIOError:
        logger.info("🚫 Another instance is already running. Exiting.")
        sys.exit(1)


    if not any([args.daily, args.alert, args.monthly]):
        is_alert = True
        is_daily = False
        is_monthly = False
    else:
        is_daily = args.daily
        is_alert = args.alert
        is_monthly = args.monthly
    vulnerabilities = load_json_file(VULN_FILE)
    keywords = load_json_file(KEYWORDS_FILE)
    if not vulnerabilities or not keywords:
        logger.info("Nothing to process.")
        return

    # Filter and extract vendor names
    vendor_names = {
            entry.split(":")[0].strip()
            for entry in keywords
            if not entry.startswith("!")
    }

    # Sort and join
    vendor_line = ", ".join(sorted(vendor_names))



    #vendor_line = ", ".join(sorted(keywords))
    logger.info(f"🔍 Filtering vulnerabilities for vendors: {vendor_line}")
    if is_daily:
        sent_ids = load_sent_ids(SENT_IDS_DAILY_FILE)
        matches = filter_vulns(vulnerabilities, keywords)
        new_matches = [v for v in matches if v["id"] not in sent_ids]
        if new_matches:
            title = "Daily Vulnerability Vendors Report"
            html_content, saved_path = daily_report(new_matches, vendor_line,title)
            send_html_email("📆 " + title, html_content, dry_run=args.dry_run,type="Daily")
            logger.info(f"📁 Saved HTML report to {saved_path}")
            if not args.dry_run:
                sent_ids.update(v["id"] for v in new_matches)
                save_sent_ids(SENT_IDS_DAILY_FILE, sent_ids)
        else:
            if not NOVULN:
                logger.info("📭 No new vulnerabilities and NOVULN=False — Skipping daily email.")
            else:
                title = "Daily Vulnerability Vendors Report"
                today = now.strftime("%B %d, %Y")
                report_title = f"{title} - {today}"
                report_url = f"{MONTHLY_URL}/{today}.html"
                empty_html = f"""
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>{report_title}</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body>
                    <div class="container mt-4">
                        <h2><i class="fa-regular fa-calendar-days"></i> {report_title}</h2>
                        
                        <p class="alert alert-info"><strong>No new vulnerabilities</strong> matched the configured vendors.</p>
                        <p><strong>Vendors list:</strong> {vendor_line}</p>
                    </div>
                    {footer_html}
                </body>
                </html>
                """
                send_html_email("📭  " + title + " – No new vulnerabilities", empty_html, dry_run=args.dry_run,type="Daily")
    elif is_alert:
        sent_ids = load_sent_ids(SENT_IDS_ALERT_FILE)
        matches = filter_vulns(vulnerabilities, keywords, severity_filter=True)
        new_matches = [v for v in matches if v["id"] not in sent_ids]
        if new_matches:
            title = f"Urgent Alert - High Severity CVEs (CVSS ≥ {MIN_CVSS_TO_ALERT})"
            html_content = alert(new_matches, vendor_line,title)
            send_html_email("🚨 " + title, html_content, dry_run=args.dry_run, high_priority=True,type="Alert")
            if not args.dry_run:
                sent_ids.update(v["id"] for v in new_matches)
                save_sent_ids(SENT_IDS_ALERT_FILE, sent_ids)
        else:
            logger.info("No new high-severity vulnerabilities to alert.")
    elif is_monthly:
        #now = datetime.now()
        first_day_this_month = datetime(now.year, now.month, 1)
        last_month_end = first_day_this_month - timedelta(days=1)
        month_year = last_month_end.strftime("%B %Y")
        matches = filter_vulns(vulnerabilities, keywords)
        last_month_matches = filter_last_month(matches)
        html_content, html_path = monthly_summary(last_month_matches, keywords, month_year)
        send_html_email(f"📊 Monthly Vulnerability Summary – {month_year}", html_content, dry_run=args.dry_run,type="Monthly")
        logger.info(f"📁 Saved monthly summary to {html_path}")

if __name__ == "__main__":
    try:
        main()
    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
            lock_file.close()
            logger.debug("🔓 Lock released and file closed.")
        except Exception as e:
            logger.warning(f"⚠️ Failed to release lock properly: {e}")
