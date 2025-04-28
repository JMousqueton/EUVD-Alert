import curses
import json
import os
from datetime import datetime
from dotenv import load_dotenv


# Load the .env file
if not os.path.exists(".env"):
    print("[ERROR] .env file not found. Please create it with VULN_FILE=...")
    sys.exit(1)

load_dotenv()

DB_FILE = os.getenv("VULN_FILE")

if not DB_FILE:
    print("[ERROR] VULN_FILE is not defined in .env file.")
    sys.exit(1)

if not os.path.exists(DB_FILE):
    print(f"[ERROR] VULN_FILE points to '{DB_FILE}' but file does not exist.")
    sys.exit(1)

def show_help_popup(stdscr):
    h, w = stdscr.getmaxyx()
    popup_h = 20
    popup_w = 70
    start_y = (h - popup_h) // 2
    start_x = (w - popup_w) // 2

    win = curses.newwin(popup_h, popup_w, start_y, start_x)
    win.border()
    win.attron(curses.color_pair(2))
    win.addstr(1, 2, "Help - EUVD Browser Keys and Legend")
    win.addstr(3, 2, "Navigation:")
    win.addstr(4, 4, "↑/↓ : Move up/down one line")
    win.addstr(5, 4, "→ : Page down")
    win.addstr(6, 4, "← : Page up")
    win.addstr(7, 2, "Sorting:")
    win.addstr(8, 4, "d : Sort by Published Date (newest first)")
    win.addstr(9, 4, "D : Sort by Published Date (oldest first)")
    win.addstr(10, 4, "u : Sort by Updated Date (newest first)")
    win.addstr(11, 4, "U : Sort by Updated Date (oldest first)")
    win.addstr(12, 4, "v : Sort by Vendor (A to Z)")
    win.addstr(13, 4, "V : Sort by Vendor (Z to A)")
    win.addstr(14, 4, "C : Sort by Severity (highest first)")
    win.addstr(15, 2, "Other:")
    win.addstr(16, 4, "s : Search by vendor")
    win.addstr(17, 4, "N : Toggle hide/show unknown vendors")
    win.addstr(18, 4, "Legend: 🟢 Low | 🟡 Medium | 🟠 High | 🔴 Critical")
    win.addstr(popup_h-2, 2, "Press any key to return")
    win.attroff(curses.color_pair(2))
    win.refresh()
    win.getch()




def load_db():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def get_vendor(vuln):
    vendors = vuln.get("enisaIdVendor", [])
    if vendors:
        return vendors[0].get("vendor", {}).get("name", "Unknown Vendor")
    return "Unknown Vendor"

def get_date_updated(vuln):
    return vuln.get("dateUpdated", "Unknown Date")

def get_score(vuln):
    return vuln.get("baseScore", "N/A")

def get_score_emoji(score):
    try:
        score = float(score)
    except Exception:
        return "⚪"  # Unknown score
    if score >= 9.0:
        return "🔴"
    elif score >= 7.0:
        return "🟠"
    elif score >= 4.0:
        return "🟡"
    else:
        return "🟢"

def parse_date(date_str):
    try:
        return datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p")
    except Exception:
        return datetime.min  # fallback if parsing fails

def filter_vulns(vulns, hide_unknown_vendor, search_query):
    filtered = []
    for v in vulns:
        vendor = get_vendor(v).lower()
        if hide_unknown_vendor and vendor in ("unknown vendor", "n/a"):
            continue
        if search_query and search_query.lower() not in vendor:
            continue
        filtered.append(v)
    return filtered

def draw_border(stdscr):
    h, w = stdscr.getmaxyx()
    stdscr.border()
    title = " EUVD Browser by Julien Mousqueton "
    stdscr.addstr(0, max((w - len(title)) // 2, 0), title, curses.color_pair(3))

def draw_menu(stdscr, all_vulns, filtered_vulns, current_idx, start_idx, hide_unknown_vendor, search_query):
    stdscr.clear()
    draw_border(stdscr)
    h, w = stdscr.getmaxyx()

    max_visible_items = h - 6  # screen height - borders and footers

    for idx in range(max_visible_items):
        vuln_idx = start_idx + idx
        if vuln_idx >= len(filtered_vulns):
            break

        vuln = filtered_vulns[vuln_idx]
        x = 2
        y = idx + 1

        vuln_id = vuln.get("id", "N/A")
        vendor = get_vendor(vuln)
        date_updated = get_date_updated(vuln)
        score = get_score(vuln)
        emoji = get_score_emoji(score)
        line = f"{emoji} {vuln_id} - {vendor} - Updated: {date_updated} - Score: {score}"

        if vuln_idx == current_idx:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, line[:w-4])
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.addstr(y, x, line[:w-4])

    stdscr.attron(curses.color_pair(2))
    vendor_mode = "HIDE Unknown Vendors" if hide_unknown_vendor else "SHOW All Vendors"
    search_mode = f" | Search Vendor: '{search_query}'" if search_query else ""
    stdscr.addstr(h-4, 2, f"Mode: {vendor_mode}{search_mode}")
    stdscr.addstr(h-3, 2, f"Showing {len(filtered_vulns)} vulnerabilities")
    stdscr.addstr(h-2, 2, "↑/↓ Navigate | Enter View | d/D/u/U/v/V/C Sort | N Toggle Vendor | s Search | q Quit")
    stdscr.attroff(curses.color_pair(2))
    stdscr.refresh()

def draw_details(stdscr, vuln):
    # Handle references better (split by newline, join with " - ")
    references = vuln.get('references', '').strip()
    if references:
        ref_list = references.strip().splitlines()
        ref_display = " - ".join(ref.strip() for ref in ref_list if ref.strip())
    else:
        ref_display = "N/A"


    aliases = vuln.get('aliases', '').strip()
    if aliases:
        alias_list = aliases.strip().splitlines()
        alias_display = ", ".join(alias.strip() for alias in alias_list if alias.strip())
    else:
        alias_display = "N/A"

    stdscr.clear()
    draw_border(stdscr)
    h, w = stdscr.getmaxyx()

    details = [
        f"ID: {vuln.get('id', 'N/A')}",
        f"Vendor: {get_vendor(vuln)}",
        f"Description: {vuln.get('description', 'N/A')}",
        f"Published: {vuln.get('datePublished', 'N/A')}",
        f"Updated: {vuln.get('dateUpdated', 'N/A')}",
        f"Base Score: {vuln.get('baseScore', 'N/A')}",
        f"CVSS Vector: {vuln.get('baseScoreVector', 'N/A')}",
        f"References: {ref_display}",
        f"Aliases: {alias_display}",
    ]

    for idx, line in enumerate(details):
        if idx >= h - 3:
            break
        stdscr.addstr(idx + 1, 2, line[:w-4])

    stdscr.attron(curses.color_pair(2))
    stdscr.addstr(h-2, 2, "ESC to go back | q to quit")
    stdscr.attroff(curses.color_pair(2))
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        if key == 27:  # ESC
            break
        elif key == ord('q'):  # quit
            raise SystemExit(0)  

def get_search_query(stdscr):
    h, w = stdscr.getmaxyx()
    popup_h = 5
    popup_w = 80
    start_y = 2
    start_x = (w - popup_w) // 2

    win = curses.newwin(popup_h, popup_w, start_y, start_x)
    win.border()
    win.attron(curses.color_pair(2))

    prompt = "Enter vendor search keyword (blank to reset): "
    win.addstr(2, 2, prompt)
    win.refresh()

    curses.echo()
    search = win.getstr(2, 2 + len(prompt)).decode('utf-8').strip()
    curses.noecho()
    return search

def main(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)

    all_vulns = load_db()
    hide_unknown_vendor = False
    search_query = ""
    vulns = filter_vulns(all_vulns, hide_unknown_vendor, search_query)
    current_idx = 0
    start_idx = 0

    while True:
        h, w = stdscr.getmaxyx()
        max_visible_items = h - 6

        vulns = filter_vulns(all_vulns, hide_unknown_vendor, search_query)
        if not vulns:
            current_idx = 0
            start_idx = 0
        else:
            current_idx = max(0, min(current_idx, len(vulns) - 1))
            start_idx = max(0, min(start_idx, current_idx))

            if current_idx < start_idx:
                start_idx = current_idx
            if current_idx >= start_idx + max_visible_items:
                start_idx = current_idx - max_visible_items + 1

        draw_menu(stdscr, all_vulns, vulns, current_idx, start_idx, hide_unknown_vendor, search_query)

        key = stdscr.getch()

        if key == curses.KEY_UP:
            if current_idx > 0:
                current_idx -= 1
        elif key == curses.KEY_DOWN:
            if current_idx < len(vulns) - 1:
                current_idx += 1
        elif key == curses.KEY_RIGHT:
            if current_idx < len(vulns) - 1:
                current_idx = min(current_idx + max_visible_items, len(vulns) - 1)
        elif key == curses.KEY_LEFT:
            if current_idx > 0:
                current_idx = max(current_idx - max_visible_items, 0)
        elif key == ord('\n') or key == curses.KEY_ENTER:
            if vulns:
                draw_details(stdscr, vulns[current_idx])
        elif key == ord('d'):
            all_vulns.sort(key=lambda v: parse_date(v.get('datePublished', '')), reverse=True)
        elif key == ord('D'):
            all_vulns.sort(key=lambda v: parse_date(v.get('datePublished', '')), reverse=False)
        elif key == ord('u'):
            all_vulns.sort(key=lambda v: parse_date(v.get('dateUpdated', '')), reverse=True)
        elif key == ord('U'):
            all_vulns.sort(key=lambda v: parse_date(v.get('dateUpdated', '')), reverse=False)
        elif key == ord('v'):
            all_vulns.sort(key=lambda v: get_vendor(v).lower())
        elif key == ord('V'):
            all_vulns.sort(key=lambda v: get_vendor(v).lower(), reverse=True)
        elif key == ord('C'):
            all_vulns.sort(key=lambda v: float(v.get('baseScore', 0.0)), reverse=True)
        elif key == ord('N'):
            hide_unknown_vendor = not hide_unknown_vendor
        elif key == ord('s'):
            search_query = get_search_query(stdscr)
        elif key == ord('?'):
            show_help_popup(stdscr)
        elif key == ord('q'):
            break

if __name__ == "__main__":
    curses.wrapper(main)
