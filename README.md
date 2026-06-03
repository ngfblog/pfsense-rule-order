# pfsense-rule-order

Automatically enforces firewall rule order in pfSense CE based on a numeric prefix in the rule description.

## The Problem

pfSense always adds new firewall rules to the **bottom** of the list. After adding a rule, you must manually drag it to the correct position. If you forget, your rule order silently breaks — with real security consequences.

## The Solution

Add a numeric prefix to your rule descriptions in the pfSense GUI:

```
01 | Zoom UDP
02 | Zoom TCP
03 | Block IoT from accessing internal LAN
04 | Allow LAN to Whitelisted Internal Services
```

A script runs via cron every few minutes, reads `config.xml`, sorts prefixed rules by number per interface, writes the config back, and reloads the firewall filter — automatically.

**Rules that are never touched:**
- pfBlockerNG auto rules (`pfB_*`)
- Floating rules
- Tailscale interface rules

**Sorting is per-interface** — LAN, WAN, LAN30 (opt1), etc. are sorted independently.

---

## How It Works

pfSense stores all firewall rules as `<rule>` elements inside `<filter>` in `/cf/conf/config.xml`. The order of elements in the XML is the order rules are evaluated.

The script:
1. Parses `config.xml`
2. Groups rules by interface
3. For rules **without** a prefix → assigns one based on current position
4. For rules **with** a prefix → respects it (user or script assigned)
5. Sorts all prefixed rules by number within each interface
6. Writes `config.xml` back atomically
7. Creates a backup before every change
8. Reloads the firewall filter

---

## Requirements

- pfSense CE 2.7.x
- Python 3.x — verify with: `ls /usr/local/bin/python3*`
- Run as root

---

## Installation

### 1. Find your Python binary

```bash
ls /usr/local/bin/python3*
```

Note the binary name (e.g. `python3.11`) for use below.

### 2. Copy the script

```bash
cp pfsense_rule_order.py /root/Scripts/
chmod +x /root/Scripts/pfsense_rule_order.py
```

### 3. Configure

Edit the **CONFIGURATION** section at the top of `pfsense_rule_order.py`:

```python
CONFIG_XML          = "/cf/conf/config.xml"
BACKUP_DIR          = "/cf/conf/rule_order_backups"
LOG_FILE            = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS         = 10
DRY_RUN             = False
APPLY_RULES         = True
MANAGED_INTERFACES  = ["wan", "lan", "opt1"]  # add opt2, opt3 etc. as needed

# Optional Gotify / ntfy notification
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL          = ""
```

> **MANAGED_INTERFACES** uses pfSense internal interface names:
> `wan`, `lan`, `opt1` (first optional = LAN30), `opt2`, etc.

### 4. First run — dry-run

Make sure your rules are in the correct order in the GUI first, then run:

```bash
python3 /root/Scripts/pfsense_rule_order.py --dry-run
```

Review the output — it shows exactly which prefixes will be added and in what order.

### 5. Apply

```bash
python3 /root/Scripts/pfsense_rule_order.py
```

This will add numeric prefixes to all managed rules and reload the firewall.

### 6. Add to cron

In the pfSense GUI: **Services > Cron > Add**

| Field   | Value |
|---------|-------|
| Minute  | `*/5` |
| Hour    | `*`   |
| Day     | `*`   |
| Month   | `*`   |
| Weekday | `*`   |
| User    | `root` |
| Command | `python3 /root/Scripts/pfsense_rule_order.py` |

> If `python3` is not found, use the full path from step 1 (e.g. `python3.11`)

---

## Numbering Tips

- Use two-digit numbers: `01`, `02`, `03` — for consistent sorting
- Leave gaps if you add rules often: `10`, `20`, `30`
- The last blocking rule must always have the highest number on that interface
- pfBlockerNG rules (`pfB_*`), Floating, and Tailscale rules need no prefix — they are never moved

---

## Example Output

```
2026-06-03 06:36:35 [INFO] === pfsense-rule-order v1.0.0 ===
2026-06-03 06:36:35 [INFO] [LAN] Prefix added: 'Block IoT' → '03 | Block IoT'
2026-06-03 06:36:35 [INFO] Backup saved: /cf/conf/rule_order_backups/config_20260603_063635.xml
2026-06-03 06:36:35 [INFO] config.xml updated successfully.
2026-06-03 06:36:35 [INFO] Filter reloaded successfully.
2026-06-03 06:36:35 [INFO] === Done ===
```

When rules are already in correct order:
```
2026-06-03 06:42:09 [INFO] [WAN] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] [LAN] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] [OPT1] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] All interfaces already correct. Nothing to do.
```

---

## License

MIT
