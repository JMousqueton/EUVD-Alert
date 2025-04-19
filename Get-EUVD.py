import requests
import json
import sys
from datetime import datetime, timedelta, UTC
import os
from dotenv import load_dotenv
import logging
import fcntl
import argparse

# Load environment variables
load_dotenv()

# Add argparse for --debug
parser = argparse.ArgumentParser(description="Fetch and update ENISA EUVD vulnerabilities.")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
args = parser.parse_args()

# Logging setup
log_level = logging.DEBUG if args.debug else logging.INFO
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

if args.debug:
    logger.debug("🐞 Debug logging is enabled.")

# Config
VULN_FILE = os.getenv("VULN_FILE", "euvd.json")
SENT_IDS_DAILY_FILE = os.getenv("SENT_IDS_DAILY_FILE", "sent_ids_daily.json")
SENT_IDS_ALERT_FILE = os.getenv("SENT_IDS_ALERT_FILE", "sent_ids_alert.json")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))

# Output and state files
output_file = VULN_FILE
sent_files = [SENT_IDS_DAILY_FILE, SENT_IDS_ALERT_FILE]

# Lock file to prevent multiple instances
lock_file_path = os.getenv("LOCK_FILE", "/tmp/euvd.lock")
lock_file = open(lock_file_path, "w")

try:
    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    logger.debug("🔒 Lock acquired successfully.")
except BlockingIOError:
    logger.info("🚫 Another instance is already running. Exiting.")
    sys.exit(1)

# Date range
today = datetime.now(UTC).date()
yesterday = today - timedelta(days=1)
from_date = yesterday.isoformat()
to_date = today.isoformat()

logger.info(f"📅 Fetching vulnerabilities from {from_date} to {to_date}")

# User-Agent headers
headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    )
}

# Load existing data
if os.path.isfile(output_file):
    logger.info(f"📂 Found existing file: {output_file}")
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            existing_data = json.load(f)
            logger.info(f"🔄 Loaded {len(existing_data)} existing entries")
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"⚠️ Failed to read existing file: {e}")
        existing_data = []
else:
    logger.info("🆕 No existing file found — starting fresh")
    existing_data = []

# Paginated API request
logger.info("📡 Requesting ENISA EUVD API...")
all_new_data = []
page = 0
page_size = 100

while True:
    url = (
        "https://euvdservices.enisa.europa.eu/api/vulnerabilities"
        f"?assigner=&product=&vendor=&text=&fromDate={from_date}&toDate={to_date}"
        f"&fromScore=0&toScore=10&fromEpss=0&toEpss=100&exploited=false"
        f"&page={page}&size={page_size}"
    )

    try:
        response = requests.get(url, headers=headers)
        if args.debug:
            logger.debug(f"🌐 URL requested: {response.url}")
            logger.debug(f"📤 Headers: {response.request.headers}")
            logger.debug(f"📥 Status Code: {response.status_code}")
            logger.debug(f"📦 Raw Response (first 500 chars): {response.text[:500]}")

        response.raise_for_status()
        api_response = response.json()

        items = api_response.get("items", [])
        total = api_response.get("total", 0)

        logger.info(f"📄 Page {page + 1}: {len(items)} entries received")
        if not items:
            break

        all_new_data.extend(items)

        if len(all_new_data) >= total:
            break

        page += 1

    except requests.RequestException as e:
        logger.error(f"❌ Network error: {e}")
        exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"❌ JSON error: {e}")
        exit(1)

logger.info(f"📦 Total entries fetched: {len(all_new_data)}")

# Merge and update entries
existing_dict = {entry.get("id"): entry for entry in existing_data}
added_count = 0
updated_count = 0
updated_ids = []

for new_entry in all_new_data:
    entry_id = new_entry.get("id")
    new_date = datetime.strptime(new_entry.get("dateUpdated"), "%b %d, %Y, %I:%M:%S %p")

    if entry_id not in existing_dict:
        existing_dict[entry_id] = new_entry
        added_count += 1
    else:
        existing_date = datetime.strptime(
            existing_dict[entry_id].get("dateUpdated"), "%b %d, %Y, %I:%M:%S %p"
        )
        if new_date > existing_date:
            existing_dict[entry_id] = new_entry
            updated_ids.append(entry_id)
            updated_count += 1

logger.info(f"➕ New entries added: {added_count}")
logger.info(f"🔁 Existing entries updated: {updated_count}")

# Clean up sent_ids files
for sent_file in sent_files:
    if os.path.isfile(sent_file):
        try:
            with open(sent_file, "r", encoding="utf-8") as f:
                sent_ids = set(json.load(f))
        except Exception as e:
            logger.warning(f"⚠️ Could not read '{sent_file}': {e}")
            sent_ids = set()

        original_count = len(sent_ids)
        sent_ids.difference_update(updated_ids)
        removed_count = original_count - len(sent_ids)

        try:
            with open(sent_file, "w", encoding="utf-8") as f:
                json.dump(sorted(list(sent_ids)), f, indent=2)
            logger.info(f"🧹 Removed {removed_count} outdated ID(s) from '{sent_file}'")
        except Exception as e:
            logger.error(f"❌ Failed to write '{sent_file}': {e}")
    else:
        logger.info(f"📁 File '{sent_file}' not found — skipping")

# Purge entries older than RETENTION_DAYS
cutoff_date = datetime.now(UTC) - timedelta(days=RETENTION_DAYS)
purged_dict = {
    entry_id: entry
    for entry_id, entry in existing_dict.items()
    if datetime.strptime(entry.get("dateUpdated"), "%b %d, %Y, %I:%M:%S %p").replace(tzinfo=UTC) > cutoff_date
}

purged_count = len(existing_dict) - len(purged_dict)
logger.info(f"🗑️  Purged {purged_count} entries older than {RETENTION_DAYS} days")

# Final save
try:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(list(purged_dict.values()), f, indent=2)
    logger.info(f"💾 Data saved to {output_file} ({len(purged_dict)} entries)")
except Exception as e:
    logger.error(f"❌ Failed to save final data: {e}")
finally:
    try:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
        logger.debug("🔓 Lock released and file closed.")
    except Exception as e:
        logger.warning(f"⚠️ Failed to release lock properly: {e}")
