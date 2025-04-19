# EUVD-Alert

**EUVD-Alert** is an automated threat monitoring tool based on the ENISA Vulnerability Database (EUVD). It fetches newly published vulnerabilities daily, filters them using keywords and severity thresholds (CVSS), and generates alerts and reporting via email.

## 🔍 Features

- Daily retrieval of vulnerabilities from the ENISA EUVD API
- Filtering based on CVSS score (e.g., alert if score ≥ 8.0)
- Vendor-based filtering
- HTML report generation (daily summary and alert-specific)
- Automated email delivery with formatted vulnerability tables
- CVSS radar chart generation for visual severity analysis
- Tracking of processed vulnerabilities to avoid duplicates

## ⚙️ Configuration

All settings are managed via the `.env` file:

```dotenv
VULN_FILE=euvd.json
KEYWORDS_FILE=vendors.json
SENT_IDS_DAILY_FILE=sent_ids_daily.json
SENT_IDS_ALERT_FILE=sent_ids_alert.json
MIN_CVSS_TO_ALERT=8
RADAR_FOLDER=./web/radars
DAILY_FOLDER=./web/daily
RADAR_URL=https://vuln.mousqueton.io/radars
DAILY_URL=https://vuln.mousqueton.io/daily
MAIL_SERVER=smtp.example.com
MAIL_PORT=465
MAIL_USERNAME=you@example.com
MAIL_PASSWORD=yourpassword
MAIL_FROM=you@example.com
MAIL_TO=alerts@example.com
LOCK_FILE=/tmp/euvd.lock
```

## 📬 Email Output

Emails are sent with HTML-formatted tables and include:

- Alert mode: When critical CVEs are detected based on keywords and severity
- Daily report: Summary of all vulnerabilities published on the day with a link to the website

## 📊 Radar Charts

Each vulnerability report includes a radar chart visualizing the CVSS vector components, offering a quick look at the severity profile.

![Radar for EUVD-2025-11786](https://vuln.mousqueton.io/radars/EUVD-2025-11786.png "EUVD-2025-11786")

## 🕹️ Usage

```bash
python3 euvd-alert.py --daily       # For daily report (vendors match)
python3 euvd-alert.py --alert       # For alert mode (severity & vendors match)
python3 euvd-alert.py --monthly     # Monthly vendors/CVSS matrix summary
```

## 📁 Output Files

- HTML reports: stored in `./web/daily/YYYY-MM-DD.html`
- Radar charts: stored in `./web/radars/`
- Monthly reports: stored in `./web/monthly/YYYY-MM.html`

## 📌 Requirements

- Python 3.x
- Libraries: `requests`, `fcntl`, `logging`, `pytz`, `smtplib`, etc.
- Cron setup for automation (recommended)
- Webserver

## 🚧 Roadmap

- Optional Slack/Teams integration
- Web dashboard for historical CVE tracking
- Enhanced analytics and visualizations
- Export options (PDF, CSV)

## 👨‍💻 Author

Julien Mousqueton  
[LinkedIn](https://linkedin.com/in/julienmousqueton)  
GitHub: [JMousqueton](https://github.com/JMousqueton)

## 🛡 License

This project is licensed under the GNU General Public License v3.0.
See the `LICENSE` file for more details.
