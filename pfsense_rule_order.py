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
  python3 pfsense_rule_order.py            # normal run
  python3 pfsense_rule_order.py --dry-run  # preview only, no changes

Requirements:
  - pfSense CE 2.7.x
  - Python 3.x (check: ls /usr/local/bin/python*)
  - Run as root

GitHub: https://github.com/ngfblog/pfsense-rule-order
"""

import re, sys, os, shutil, logging, subprocess
from datetime import datetime
from xml.etree import ElementTree as ET

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_XML  = "/cf/conf/config.xml"
BACKUP_DIR  = "/cf/conf/rule_order_backups"
LOG_FILE    = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS = 10
DRY_RUN     = False
APPLY_RULES = True

# Interfaces to manage (internal pfSense names)
# wan, lan, opt1 (LAN30), opt2, etc.
# Floating and Tailscale are always excluded regardless of this list.
MANAGED_INTERFACES = ["wan", "lan", "opt1"]

# Optional Gotify / ntfy notification
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL      = ""
NOTIFY_PRIORITY = 5

# =============================================================================

VERSION   = "1.2.0"
PREFIX_RE = re.compile(r"^\s*(\d+)\s*\|")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


def get_prefix(text):
    if not text: return None
    m = PREFIX_RE.match(text)
    return int(m.group(1)) if m else None

def strip_prefix(text):
    if not text: return text
    return PREFIX_RE.sub("", text).strip()

def get_descr(rule):
    d = rule.find("descr")
    return (d.text or "").strip() if d is not None else ""

def set_descr(rule, text):
    d = rule.find("descr")
    if d is None: d = ET.SubElement(rule, "descr")
    d.text = text

def get_interface(rule):
    i = rule.find("interface")
    return (i.text or "").strip().lower() if i is not None else None

def is_floating(rule):
    f = rule.find("floating")
    return f is not None and (f.text or "").strip().lower() == "yes"

def is_pfblockerng(rule):
    return get_descr(rule).startswith("pfB_")

def is_tailscale(rule):
    return (get_interface(rule) or "") == "tailscale"

def should_skip(rule):
    return is_floating(rule) or is_tailscale(rule) or is_pfblockerng(rule)

def is_managed(rule):
    iface = get_interface(rule)
    if not iface or iface not in MANAGED_INTERFACES: return False
    if should_skip(rule): return False
    if rule.find("tracker") is None: return False
    if "," in iface: return False
    return True


def backup_config():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"config_{ts}.xml")
    shutil.copy2(CONFIG_XML, dst)
    log.info(f"Backup saved: {dst}")
    all_bk = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith("config_")], reverse=True)
    for old in all_bk[MAX_BACKUPS:]:
        os.remove(os.path.join(BACKUP_DIR, old))


def enforce_rule_order(config_path):
    tree = ET.parse(config_path)
    root = tree.getroot()
    filter_elem = root.find("filter")
    if filter_elem is None:
        log.error("<filter> not found in config.xml")
        return False

    # all <rule> elements in XML order
    all_rules = list(filter_elem.findall("rule"))
    if not all_rules:
        log.info("No rules found.")
        return False

    # --- Step 1: assign prefixes to unprefixed managed rules ---
    iface_managed = {}
    for rule in all_rules:
        if not is_managed(rule): continue
        iface_managed.setdefault(get_interface(rule), []).append(rule)

    prefix_changed = False
    for iface, rules in iface_managed.items():
        taken, unprefixed = {}, []
        for rule in rules:
            p = get_prefix(get_descr(rule))
            if p is not None: taken[p] = rule
            else: unprefixed.append(rule)
        counter = 1
        for rule in unprefixed:
            while counter in taken: counter += 1
            new_descr = f"{counter:02d} | {strip_prefix(get_descr(rule))}"
            if get_descr(rule) != new_descr:
                log.info(f"[{iface.upper()}] Prefix added: '{get_descr(rule)}' -> '{new_descr}'")
                set_descr(rule, new_descr)
                taken[counter] = rule
                prefix_changed = True
            counter += 1

    # --- Step 2: sort per interface, detect changes ---
    iface_positions = {}
    for i, rule in enumerate(all_rules):
        if not is_managed(rule): continue
        iface_positions.setdefault(get_interface(rule), []).append(i)

    iface_sorted = {}
    order_changed = False
    change_summary = []

    for iface, positions in iface_positions.items():
        rules = [all_rules[p] for p in positions]
        sorted_rules = sorted(rules, key=lambda r: get_prefix(get_descr(r)) or 0)
        iface_sorted[iface] = sorted_rules
        # compare by description only (not object identity)
        if [get_descr(r) for r in rules] != [get_descr(r) for r in sorted_rules]:
            order_changed = True
            for old, new in zip(rules, sorted_rules):
                if get_descr(old) != get_descr(new):
                    msg = f"[{iface.upper()}] Order: '{get_descr(new)}' moved to position of '{get_descr(old)}'"
                    log.info(msg)
                    change_summary.append(msg)
        else:
            log.info(f"[{iface.upper()}] Already correct, nothing to do.")

    if not prefix_changed and not order_changed:
        log.info("All interfaces already correct. Nothing to do.")
        return False

    if DRY_RUN:
        log.info("DRY RUN -- config.xml NOT modified.")
        return False

    # --- Step 3: swap rules IN-PLACE (preserves separators and other children) ---
    # Build new rule order using cursor per interface
    iface_cursor = {iface: 0 for iface in iface_positions}
    new_rule_order = []
    for rule in all_rules:
        if is_managed(rule):
            iface = get_interface(rule)
            new_rule_order.append(iface_sorted[iface][iface_cursor[iface]])
            iface_cursor[iface] += 1
        else:
            new_rule_order.append(rule)

    # Replace each <rule> child in filter_elem with the new rule at same position
    # This preserves separators and other non-rule children exactly where they are
    rule_children_idx = [i for i, child in enumerate(filter_elem) if child.tag == "rule"]
    for child_idx, new_rule in zip(rule_children_idx, new_rule_order):
        filter_elem[child_idx] = new_rule

    # --- Step 4: save and apply ---
    backup_config()
    tmp = config_path + ".rule_order.tmp"
    tree.write(tmp, encoding="utf-8", xml_declaration=True)
    os.replace(tmp, config_path)
    log.info("config.xml updated successfully.")

    if NOTIFY_URL and change_summary:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "title":    "pfSense: Rule Order Enforced",
                "message":  "Changes:\n" + "\n".join(change_summary),
                "priority": NOTIFY_PRIORITY,
            }).encode()
            urllib.request.urlopen(urllib.request.Request(NOTIFY_URL, data=data), timeout=5)
            log.info("Notification sent.")
        except Exception as e:
            log.warning(f"Notification failed: {e}")

    return True


def reload_filter():
    log.info("Reloading firewall filter...")
    try:
        r = subprocess.run(["/etc/rc.filter_configure_sync"], capture_output=True, text=True, timeout=60)
        if r.returncode == 0: log.info("Filter reloaded successfully.")
        else: log.error(f"filter_configure_sync failed: {r.stderr.strip()}")
    except Exception as e:
        log.error(f"Failed to reload filter: {e}")


def check_prerequisites():
    if os.geteuid() != 0:
        log.error("Must be run as root.")
        sys.exit(1)
    if not os.path.exists(CONFIG_XML):
        log.error(f"config.xml not found: {CONFIG_XML}")
        sys.exit(1)


if __name__ == "__main__":
    if "--dry-run" in sys.argv: DRY_RUN = True
    log.info(f"=== pfsense-rule-order v{VERSION} {'(DRY RUN) ' if DRY_RUN else ''}===")
    check_prerequisites()
    changed = enforce_rule_order(CONFIG_XML)
    if changed and APPLY_RULES and not DRY_RUN:
        reload_filter()
    log.info("=== Done ===")
