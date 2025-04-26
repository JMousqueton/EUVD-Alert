# EUVD-Alert

**EUVD-Alert** is an automated threat monitoring tool based on the ENISA Vulnerability Database (EUVD). It fetches newly published vulnerabilities daily, filters them using keywords and severity thresholds (CVSS), and generates alerts and reporting via email.

## 🔍 Features

- Daily retrieval of vulnerabilities from the ENISA EUVD API
- Filtering based on CVSS score (e.g., alert if score ≥ 8.0)
- Vendor-based & Product-based filtering (see [keywords.json](keyword.json))
- HTML report generation (daily summary and alert-specific)
- Automated email delivery with formatted vulnerability tables
- CVSS radar chart generation for visual severity analysis
- Tracking of processed vulnerabilities to avoid duplicates
- Add EPSS from [FIRST](https://www.first.org) 
- Logging to file feature 

## ⚙️ Configuration

All settings are managed via the `.env` file

Check [env.sample](env.sample) for explainations 

## 📬 Email Output

Emails are sent with HTML-formatted tables and include:

- Alert mode: When critical CVEs are detected based on keywords and severity
- Daily report: Summary of all vulnerabilities published on the day with a link to the website

## 📊 Radar Charts

Each vulnerability report includes a radar chart visualizing the CVSS vector components, offering a quick look at the severity profile.

![Radar for EUVD-2025-11786](https://vuln.mousqueton.io/radars/EUVD-2025-11786.png "EUVD-2025-11786")

## 📺 Demos

### Monthly report 

- [March 2025](https://vuln.mousqueton.io/monthly/2025-03.html)

## 🕹️ Usage

```bash
python3 euvd-alert.py --daily       # For daily report (vendors match)
python3 euvd-alert.py --alert       # For alert mode (severity & vendors match)
python3 euvd-alert.py --monthly     # Monthly vendors/CVSS matrix summary
```

## 🕐 Example of cron

```
5 * * * * cd /opt/EUVD-Alert ; python3 Get-EUVD.py --log > /dev/null 2>&1 python3 AlertAndReport.py -A --log > /dev/null 2>&1
0 5 * * * cd /opt/EUVD-Alert ; python3 AlertAndReport.py -D --log > /dev/null 2>&1
0 4 1 * * cd /opt/EUVD-Alert && /usr/bin/python3 AlertAndReport.py -M --log > /dev/null 2>&1
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

- ~~Add EPSS from [FIRST](https://www.first.org)~~ ✅ 
- ~~Generate a HTML page also for alert~~ ✅ 
- ~~Filtering on product-based~~ ✅
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
