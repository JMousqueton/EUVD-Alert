import os
import sys
import json
import fcntl
import argparse
import logging
from datetime import datetime, timedelta, UTC

import requests
from dotenv import load_dotenv

# Constants
DATE_FMT = "%b %d, %Y, %I:%M:%S %p"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    )
}

# Load .env variables
load_dotenv()

# CLI args
parser = argparse.ArgumentParser(description="Fetch and update ENISA EUVD vulnerabilities.")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
parser.add_argument("--log", action="store_true", help="Enable logging to file if LOG_FILE is set in .env")
args = parser.parse_args()

# Logging
log_level = logging.DEBUG if args.debug else logging.INFO
log_handlers = [logging.StreamHandler()]
logger = logging.getLogger(__name__)

LOG_FILE_PATH = os.getenv("LOG_FILE", "").strip()
if args.log and LOG_FILE_PATH:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log_handlers.append(file_handler)
elif args.log:
    print("⚠️  --log flag used but LOG_FILE is not set in .env", file=sys.stderr)

logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s", handlers=log_handlers)

if args.log and LOG_FILE_PATH:
    logger.info(f"🚀 Running script: {os.path.abspath(sys.argv[0])}")
    logger.info(f"📂 File logging enabled: {LOG_FILE_PATH}")
if args.debug:
    logger.debug("🐞 Debug logging is enabled.")

# Config
VULN_FILE = os.getenv("VULN_FILE", "euvd.json")
SENT_IDS_DAILY_FILE = os.getenv("SENT_IDS_DAILY_FILE", "sent_ids_daily.json")
SENT_IDS_ALERT_FILE = os.getenv("SENT_IDS_ALERT_FILE", "sent_ids_alert.json")
LOCK_FILE = os.getenv("LOCK_FILE", "/tmp/euvd.lock")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))

# Prevent concurrent execution
with open(LOCK_FILE, "w") as lock_file:
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logger.info("🔒 Lock acquired successfully.")
    except BlockingIOError:
        logger.info("🚫 Another instance is already running. Exiting.")
        sys.exit(1)

    # Date Range
    today = datetime.now(UTC).date()
    from_date = (today - timedelta(days=1)).isoformat()
    to_date = today.isoformat()
    logger.info(f"📅 Fetching vulnerabilities from {from_date} to {to_date}")

    # Load existing entries
    if os.path.isfile(VULN_FILE):
        logger.info(f"📂 Found existing file: {VULN_FILE}")
        try:
            with open(VULN_FILE, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
            logger.info(f"🔄 Loaded {len(existing_data)} existing entries")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"⚠️ Failed to read existing file: {e}")
            existing_data = []
    else:
        logger.info("🆕 No existing file found — starting fresh")
        existing_data = []

    # Fetch API data
    logger.info("📡 Requesting ENISA EUVD API...")
    all_new_data = []
    page = 0
    page_size = 100

    while True:
        url = (
            "https://euvdservices.enisa.europa.eu/api/vulnerabilities"
            f"?fromDate={from_date}&toDate={to_date}&page={page}&size={page_size}"
        )

        try:
            response = requests.get(url, headers=HEADERS)
            if args.debug:
                logger.debug(f"🌐 URL: {response.url}")
                logger.debug(f"📥 Status: {response.status_code}")
                logger.debug(f"📦 Response (500 chars): {response.text[:500]}...")

            response.raise_for_status()
            data = response.json()
            items = data.get("items", [])
            total = data.get("total", 0)

            logger.info(f"📄 Page {page + 1}: {len(items)} entries")
            if not items:
                break

            all_new_data.extend(items)
            if len(all_new_data) >= total:
                break
            page += 1

        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.error(f"❌ Error fetching data: {e}")
            sys.exit(1)

    logger.info(f"📦 Total fetched: {len(all_new_data)}")

    # Merge entries
    existing_dict = {e["id"]: e for e in existing_data}
    added_count = 0
    updated_count = 0
    updated_ids = []

    for entry in all_new_data:
        entry_id = entry["id"]
        new_date = datetime.strptime(entry["dateUpdated"], DATE_FMT)
        if entry_id not in existing_dict:
            existing_dict[entry_id] = entry
            added_count += 1
        else:
            existing_date = datetime.strptime(existing_dict[entry_id]["dateUpdated"], DATE_FMT)
            if new_date > existing_date:
                existing_dict[entry_id] = entry
                updated_ids.append(entry_id)
                updated_count += 1

    logger.info(f"📝 Added: {added_count}")
    logger.info(f"🔁 Updated: {updated_count}")

    # Update sent_ids files
    for sent_file in [SENT_IDS_DAILY_FILE, SENT_IDS_ALERT_FILE]:
        if not os.path.isfile(sent_file):
            logger.info(f"📁 File '{sent_file}' not found — skipping")
            continue

        try:
            with open(sent_file, "r", encoding="utf-8") as f:
                sent_ids = set(json.load(f))
            original_count = len(sent_ids)
            sent_ids.difference_update(updated_ids)
            removed_count = original_count - len(sent_ids)

            with open(sent_file, "w", encoding="utf-8") as f:
                json.dump(sorted(sent_ids), f, indent=2)

            logger.info(f"🧹 Removed {removed_count} outdated ID(s) from '{sent_file}'")
        except Exception as e:
            logger.warning(f"⚠️ Error processing '{sent_file}': {e}")

    # Retention policy
    cutoff = datetime.now(UTC) - timedelta(days=RETENTION_DAYS)
    purged_dict = {
        eid: entry for eid, entry in existing_dict.items()
        if datetime.strptime(entry["dateUpdated"], DATE_FMT).replace(tzinfo=UTC) > cutoff
    }
    logger.info(f"🗑️  Purged {len(existing_dict) - len(purged_dict)} entries older than {RETENTION_DAYS} days")

    # Save final result
    try:
        with open(VULN_FILE, "w", encoding="utf-8") as f:
            json.dump(list(purged_dict.values()), f, indent=2)
        logger.info(f"💾 Saved to {VULN_FILE} ({len(purged_dict)} entries)")
    except Exception as e:
        logger.error(f"❌ Failed to save: {e}")
    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
            logger.info("🔓 Lock released.")
        except Exception as e:
            logger.warning(f"⚠️ Failed to release lock: {e}")
