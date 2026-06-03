#!/usr/bin/env python3
"""
pfsense-rule-order — Firewall Rule Order Enforcer
==================================================
1. Backs up config.xml
2. Adds numeric prefix to all manual rule descriptions (per interface)
3. Sorts rules by their prefix number (per interface)
4. Writes config.xml back and reloads the firewall filter

Rules that are NEVER touched:
  - Floating rules (<floating>yes</floating>)
  - Tailscale interface rules
  - pfBlockerNG auto rules (descr starts with "pfB_")

Usage:
  python3.11 pfsense_rule_order.py            # normal run
  python3.11 pfsense_rule_order.py --dry-run  # preview only, no changes

Requirements:
  - pfSense CE 2.7.x
  - Python 3.x (check: ls /usr/local/bin/python*)
  - Run as root

GitHub: https://github.com/ngfblog/pfsense-rule-order
"""

import re
import sys
import os
import shutil
import logging
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_XML  = "/cf/conf/config.xml"
BACKUP_DIR  = "/cf/conf/rule_order_backups"
LOG_FILE    = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS = 10
DRY_RUN     = False   # True = preview only, do NOT write or apply
APPLY_RULES = True    # True = reload firewall filter after sorting

# Interfaces to manage (internal pfSense names)
# wan, lan, opt1 (LAN30), opt2, etc.
# Floating and Tailscale are always excluded regardless of this list.
MANAGED_INTERFACES = ["wan", "lan", "opt1"]

# Optional Gotify / ntfy notification
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL      = ""
NOTIFY_PRIORITY = 5

# =============================================================================

VERSION = "1.0.0"

# Prefix pattern: "06 | Description" or "6 | Description"
PREFIX_RE = re.compile(r"^\s*(\d+)\s*\|\s*")

# --- Logging -----------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

# --- Checks ------------------------------------------------------------------

def check_prerequisites():
    """Verify we can actually run safely."""
    errors = []

    # Must be root
    if os.geteuid() != 0:
        errors.append("Must be run as root.")

    # config.xml must exist
    if not os.path.exists(CONFIG_XML):
        errors.append(f"config.xml not found: {CONFIG_XML}")

    if errors:
        for e in errors:
            log.error(e)
        sys.exit(1)

# --- Helpers -----------------------------------------------------------------

def get_prefix(text):
    """Return int prefix if description starts with 'NN |', else None."""
    if not text:
        return None
    m = PREFIX_RE.match(text)
    return int(m.group(0).split("|")[0].strip()) if m else None

def strip_prefix(text):
    """Remove existing prefix from description, return clean name."""
    if not text:
        return text
    return PREFIX_RE.sub("", text).strip()

def get_descr(rule):
    d = rule.find("descr")
    return (d.text or "").strip() if d is not None else ""

def set_descr(rule, text):
    d = rule.find("descr")
    if d is None:
        d = ET.SubElement(rule, "descr")
    d.text = text

def get_interface(rule):
    iface = rule.find("interface")
    return (iface.text or "").strip().lower() if iface is not None else None

def is_floating(rule):
    f = rule.find("floating")
    return f is not None and (f.text or "").strip().lower() == "yes"

def is_pfblockerng(rule):
    """pfBlockerNG auto rules start with 'pfB_'."""
    return get_descr(rule).startswith("pfB_")

def is_tailscale(rule):
    return (get_interface(rule) or "") == "tailscale"

def should_skip(rule):
    """Return True for rules we never touch."""
    return is_floating(rule) or is_tailscale(rule) or is_pfblockerng(rule)

# --- Backup ------------------------------------------------------------------

def backup_config():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"config_{ts}.xml")
    shutil.copy2(CONFIG_XML, dst)
    log.info(f"Backup saved: {dst}")
    # Prune old backups
    all_bk = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith("config_")],
        reverse=True,
    )
    for old in all_bk[MAX_BACKUPS:]:
        os.remove(os.path.join(BACKUP_DIR, old))
        log.info(f"Pruned old backup: {old}")

# --- Core --------------------------------------------------------------------

def enforce_rule_order(config_path):
    """
    Main logic:
    1. Parse config.xml
    2. For each managed interface:
       a. Find all manual rules (not floating, not tailscale, not pfB_)
       b. Rules without prefix: assign prefix based on current position
       c. Rules with prefix: keep their prefix (user/script assigned)
       d. Sort all rules by prefix number
       e. Write back preserving positions of skipped rules
    3. Save config.xml
    4. Reload filter
    """
    tree = ET.parse(config_path)
    root = tree.getroot()

    filter_elem = root.find("filter")
    if filter_elem is None:
        log.error("<filter> not found in config.xml")
        return False

    all_rules = list(filter_elem.findall("rule"))
    if not all_rules:
        log.info("No rules found.")
        return False

    # Group rules by interface, preserving global index
    # { "lan": [(global_idx, rule), ...], "wan": [...], ... }
    iface_groups = {}
    for i, rule in enumerate(all_rules):
        iface = get_interface(rule)
        if not iface or iface not in MANAGED_INTERFACES:
            continue
        if should_skip(rule):
            continue
        iface_groups.setdefault(iface, []).append((i, rule))

    any_change     = False
    change_summary = []

    for iface in MANAGED_INTERFACES:
        if iface not in iface_groups:
            continue

        indexed = iface_groups[iface]
        indices = [x[0] for x in indexed]
        rules   = [x[1] for x in indexed]

        # --- Step 1: Assign prefixes to unprefixed rules ---
        # First pass: find which position numbers are already taken
        taken_prefixes = {}  # prefix -> rule
        unprefixed     = []  # (list_index, rule)

        for list_idx, rule in enumerate(rules):
            p = get_prefix(get_descr(rule))
            if p is not None:
                taken_prefixes[p] = rule
            else:
                unprefixed.append((list_idx, rule))

        # Assign prefix to unprefixed rules based on their current position
        # Use position*2 spacing to leave room, avoid collisions with taken
        prefix_changed = False
        counter = 1
        for list_idx, rule in unprefixed:
            # Find next available prefix number
            while counter in taken_prefixes:
                counter += 1
            new_descr = f"{counter:02d} | {strip_prefix(get_descr(rule))}"
            old_descr = get_descr(rule)
            if old_descr != new_descr:
                log.info(f"[{iface.upper()}] Prefix added: '{old_descr}' → '{new_descr}'")
                change_summary.append(f"[{iface.upper()}] '{old_descr}' → '{new_descr}'")
                set_descr(rule, new_descr)
                prefix_changed = True
                taken_prefixes[counter] = rule
            counter += 1

        # --- Step 2: Sort rules by prefix ---
        sorted_rules = sorted(rules, key=lambda r: get_prefix(get_descr(r)) or 0)

        order_changed = [x[0] for x in sorted(enumerate(rules),
                         key=lambda x: get_prefix(get_descr(x[1])) or 0)] != list(range(len(rules)))

        if not prefix_changed and not order_changed:
            log.info(f"[{iface.upper()}] Already correct, nothing to do.")
            continue

        any_change = True

        # Log order changes
        for old, new in zip(rules, sorted_rules):
            if old is not new:
                msg = (f"[{iface.upper()}] Order: '{get_descr(new)}' "
                       f"moved to position of '{get_descr(old)}'")
                log.info(msg)
                change_summary.append(msg)

        # --- Step 3: Write sorted rules back at their global positions ---
        for global_idx, new_rule in zip(indices, sorted_rules):
            count = 0
            for pos, child in enumerate(list(filter_elem)):
                if child.tag == "rule":
                    if count == global_idx:
                        filter_elem.remove(child)
                        filter_elem.insert(pos, new_rule)
                        break
                    count += 1

    if not any_change:
        log.info("All interfaces already correct. Nothing to do.")
        return False

    if DRY_RUN:
        log.info("DRY RUN — config.xml NOT modified.")
        return False

    # Safe atomic write
    backup_config()
    tmp = config_path + ".rule_order.tmp"
    tree.write(tmp, encoding="utf-8", xml_declaration=True)
    os.replace(tmp, config_path)
    log.info("config.xml updated successfully.")

    # Notify
    if NOTIFY_URL and change_summary:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "title":    "pfSense: Rule Order Enforced",
                "message":  "Changes:\n" + "\n".join(change_summary),
                "priority": NOTIFY_PRIORITY,
            }).encode()
            urllib.request.urlopen(
                urllib.request.Request(NOTIFY_URL, data=data), timeout=5
            )
            log.info("Notification sent.")
        except Exception as e:
            log.warning(f"Notification failed: {e}")

    return True


def reload_filter():
    """Reload pfSense firewall filter."""
    log.info("Reloading firewall filter...")
    try:
        r = subprocess.run(
            ["/etc/rc.filter_configure_sync"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0:
            log.info("Filter reloaded successfully.")
        else:
            log.error(f"filter_configure_sync failed: {r.stderr.strip()}")
    except Exception as e:
        log.error(f"Failed to reload filter: {e}")


# --- Entry point -------------------------------------------------------------

if __name__ == "__main__":
    if "--dry-run" in sys.argv:
        DRY_RUN = True

    log.info(f"=== pfsense-rule-order v{VERSION} {'(DRY RUN) ' if DRY_RUN else ''}===")

    check_prerequisites()

    changed = enforce_rule_order(CONFIG_XML)

    if changed and APPLY_RULES and not DRY_RUN:
        reload_filter()

    log.info("=== Done ===")
