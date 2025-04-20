import sys
import json
import os
import argparse
import requests
import matplotlib.pyplot as plt
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
from collections import defaultdict

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
NOVULN = os.getenv("NOVULN", "False").lower() in ("true", "1", "yes")
LOG_FILE_PATH = os.getenv("LOG_FILE", "").strip()


current_year = now.year
copyright_year = (
    f"2025–{current_year}" if current_year > 2025 else "2025"
)

footer_html = (
    f'<footer style="text-align:center; padding:1em 0; font-size:0.9em; color:#777;">'
    f'&copy; {copyright_year} '
    f'<a href="https://teams.microsoft.com/l/chat/0/0?users=julien.mousqueton@computacenter.com" target=_blank>Julien Mousqueton</a> – All rights reserved.<br>'
    'Source : <a href="https://euvd.enisa.europa.eu/" target=_blank>ENISA</a><br><br>'
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
)



legend_html = (
    '<div class="mt-4 p-3 bg-light border rounded">'
    '<h5><i class="fa-solid fa-circle-info"></i> CVSS Radar Legend</h5>'
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

def_html = """
<div class="mt-4 p-3 bg-light border rounded">
  <h5><i class="fa-solid fa-circle-info"></i> CVSS Severity Legend</h5>
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
    
def generate_summary_card(vulns,vendor_line):
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
    vendor_list = ', '.join(f"{vendor} ({count})" for vendor, count in sorted(vendor_counts.items()))
    return f"""
    <div class="card border-primary mb-3">
      <div class="card-header bg-primary text-white"><strong>🔎 &nbsp;Summary:</strong> {nb_vulns} vulnerabilities</div>
      <div class="card-body">
        <p class="card-text">
            <strong>Severity breakdown:</strong><br>
            <span title="Critical">{cvss_severity_icon(9.5)} {severity_counts['critical']}</span> &nbsp;
            <span title="High">{cvss_severity_icon(8)} {severity_counts['high']}</span> &nbsp;
            <span title="Medium">{cvss_severity_icon(5)} {severity_counts['medium']}</span> &nbsp;
            <span title="Low">{cvss_severity_icon(2)} {severity_counts['low']}</span> &nbsp;
            <span title="Unknown">{cvss_severity_icon(0)} {severity_counts['?']}</span>             
        </p>
        <p class="card-text"><strong>Filtered vendors:</strong><br> {vendor_line}</p>
        <p class="card-text"><strong>Vulnerabilities by vendor:</strong><br> {vendor_list}</p>
      </div>
    </div>
    """

def daily_report(vulns, vendor_line,title):
    html_path = f"./web/daily/{today}.html"
    # Format the date for the title
    full_title = f"{title} - {formatted_date}"
    rows = ""
    nb_vulns = len(vulns)
    for v in vulns:
        #generate_radar_chart(v.get("baseScoreVector", ""), v["id"])
        alt_id = v.get('aliases', '').strip()
        score = v.get("baseScore", "N/A")
        icon = cvss_severity_icon(score)
        exploited = "Yes" if v.get("exploited", False) else "No"
        desc = v.get("description", "")[:200].replace("\n", " ") + "..."
        #product = ", ".join(p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", []))
        product_names = [p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", [])]
        unique_product_names = remove_duplicates_preserve_order(product_names)
        product = ", ".join(unique_product_names)
        vendor = ", ".join(vn.get("vendor", {}).get("name", "n/a") for vn in v.get("enisaIdVendor", []))
        url = f"https://euvd.enisa.europa.eu/enisa/{v['id']}"
        vector = v.get("baseScoreVector", "")
        has_radar = bool(vector and "/" in vector)
        if vendor_line:
            vendor_html = (
            f'<div style="text-align:center; font-size:0.8em; color:#777; padding-top:1em;">'
            f'Filtered on vendors: {vendor_line}'
            f'</div>'
            )
        else:
            vendor_html = ""

        if has_radar:
            generate_radar_chart(vector, v["id"], score)
            img_tag = f'<img src="{RADAR_URL}/{v["id"]}.png" class="img-fluid rounded shadow-sm" style="max-width: 150px;" alt="Radar">'
        else:
            img_tag = generate_inline_noinfo_svg()
        rows += f"""
            <tr>
                <td><a href="{url}">{v['id']}</a><br><small>{alt_id}</small></td>
                <td data-sort="{score}">{icon} {score}</td>
                <td>{exploited}</td>
                <td>{vendor}</td>
                <td>{product}</td>
                <td>{desc}</td>
                <td>{img_tag}</td>
            </tr>
        """
    report_url = f"{DAILY_URL}/{today}.html"
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
                <meta property="og:image" content="https://vuln.mousqueton.io/daily-preview.png">
                <meta property="og:image:width" content="1200">
                <meta property="og:image:height" content="630">
                <meta property="og:url" content="https://vuln.mousqueton.io/daily/{today}.html">
                <meta property="og:site_name" content="Julien Mousqueton">
                <meta property="og:logo" content="https://vuln.mousqueton.io/logo.png">

                <!-- Twitter Card Meta -->
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:title" content="Daily Vulnerability Vendors Report - {formatted_date}">
                <meta name="twitter:description" content="{nb_vulns} new vulnerabilities across {vendor_line}.">
                <meta name="twitter:image" content="https://vuln.mousqueton.io/daily-preview.png">
                <meta name="twitter:site" content="Julien Mousqueton">
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
                <h2><i class="fa-regular fa-calendar-days"></i> {full_title}</h2>
                <p>📄 <a href="{report_url}">View this report online</a></p>
                <br>
                {generate_summary_card(vulns,vendor_line)}
                <br>
                <div style="text-align:center; font-size:0.8em; color:#777; padding-top:1em;">
                    Page generated on {full_date}
                </div>
                <table id="vuln-table" class="table table-bordered table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>ID</th>
                            <th>CVSS</th>
                            <th>Exploited</th>
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
                            {{ orderable: false, targets: [4, 5, 6] }}  // Disable Product, Description, and Radar
                        ]
                        }});
                    }});
                </script>
                <div class="mt-4 p-3 bg-light border rounded">
                    {vendor_html}
                    {legend_html}
                </div>
                {footer_html}
            </body>
        </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_content, html_path

def load_json_file(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

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

def filter_vulns(vulnerabilities, keywords, severity_filter=False):
    matches = []
    for v in vulnerabilities:
        if matches_keyword(v, keywords):
            try:
                if severity_filter:
                    if float(v.get("baseScore", 0)) >= MIN_CVSS_TO_ALERT:
                        matches.append(v)
                else:
                    matches.append(v)
            except ValueError:
                continue
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


def alert(vulns, vendor_line,title):
    full_title = f"{title} - {formatted_date}"
    rows = ""
    for v in vulns:
        score = v.get("baseScore", "N/A")
        icon = cvss_severity_icon(score)
        exploited = "Yes" if v.get("exploited", False) else "No"
        desc = v.get("description", "")[:200].replace("\n", " ") + "..."
        product_names = [p.get("product", {}).get("name", "n/a") for p in v.get("enisaIdProduct", [])]
        unique_product_names = remove_duplicates_preserve_order(product_names)
        product = ", ".join(unique_product_names)
        vendor = ", ".join(vn.get("vendor", {}).get("name", "n/a") for vn in v.get("enisaIdVendor", []))
        url = f"https://euvd.enisa.europa.eu/enisa/{v['id']}"
        vector = v.get("baseScoreVector", "")
        has_radar = bool(vector and "/" in vector)
        if vendor_line:
            vendor_html = (
            f'<div style="text-align:center; font-size:0.8em; color:#777; padding-top:1em;">'
            f'Filtered on vendors: {vendor_line}'
            f'</div>'
            )
        else:
            vendor_html = ""
        if has_radar:
            generate_radar_chart(vector, v["id"], score)
            img_tag = f'<img src="{RADAR_URL}/{v["id"]}.png" class="img-fluid rounded shadow-sm" style="max-width: 150px;" alt="Radar">'
        else:
            img_tag = generate_inline_noinfo_svg()
        rows += f"""
            <tr>
                <td><a href="{url}">{v['id']}</a><br><small>{v.get("aliases", "")}</small></td>
                <td>{icon} {score}</td>
                <td>{exploited}</td>
                <td>{vendor}</td>
                <td>{product}</td>
                <td>{desc}</td>
                <td>{img_tag}</td>
            </tr>
        """
    html_content = f"""
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>{full_title}</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
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
                        background-color: #f8d7da;
                        text-align: left;
                    }}
                    h2 {{
                        color: #b02a37;
                    }}
                </style>
            </head>
            <body>
                <h2>🚨 {full_title}</h2>
                <p><strong>This is an automated alert for critical vulnerabilities.</strong></p>
                <table id="alert-table" class="table table-bordered table-hover align-middle">
                    <thead class="table-danger">
                        <tr>
                            <th>ID</th>
                            <th>CVSS</th>
                            <th>Exploited</th>
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
                <div class="mt-4 p-3 bg-light border rounded">
                    {vendor_html}
                    {legend_html}
                </div>
                    {footer_html}
            </body>
        </html>
    """
    return html_content

def monthly_summary(vulns, keywords, month_year):
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

    vendor_line = ", ".join(sorted(keywords))

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
                <meta property="og:image" content="https://vuln.mousqueton.io/daily-preview.png">
                <meta property="og:image:width" content="1200">
                <meta property="og:image:height" content="630">
                <meta property="og:url" content="https://vuln.mousqueton.io/monthly/{month_year}.html">
                <meta property="og:site_name" content="Julien Mousqueton">
                <meta property="og:logo" content="https://vuln.mousqueton.io/logo.png">

                <!-- Twitter Card Meta -->
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:title" content="Monthly Vulnerability Vendors Summarize - {month_year}">
                <meta name="twitter:description" content="In {month_year}, {nb_vulns} new vulnerabilities across {vendor_line}.">
                <meta name="twitter:image" content="https://vuln.mousqueton.io/daily-preview.png">
                <meta name="twitter:site" content="Julien Mousqueton">
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
                {generate_summary_card(vulns,vendor_line)}
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
                {def_html}
            </div>
            {footer_html}
            </body>
        </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_content, html_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--daily", "-D", action="store_true", help="Send daily report")
    parser.add_argument("--alert", "-A", action="store_true", help="Send alert report")
    parser.add_argument("--monthly", "-M", action="store_true", help="Send monthly summary")
    parser.add_argument("--dry-run", action="store_true", help="Simulate sending without actually sending emails")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")  
    parser.add_argument("--log", action="store_true", help="Enable logging to file if LOG_FILE is set in .env")  
    args = parser.parse_args()

    if args.log and LOG_FILE_PATH:
        file_handler = logging.FileHandler(LOG_FILE_PATH)
        file_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info(f"🚀 Running script: {os.path.abspath(sys.argv[0])}")
        logger.info(f"📂 File logging enabled: {LOG_FILE_PATH}")
    elif args.log:
        logger.warning("⚠️ --log flag used but LOG_FILE is not set in .env")


    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled.")

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
    vendor_line = ", ".join(sorted(keywords))
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
