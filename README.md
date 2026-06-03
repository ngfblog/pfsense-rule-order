# pfsense-rule-order

Keeps your pfSense firewall rules in the right order, automatically.

---

## Background

pfSense has a known, long-standing issue where firewall rules get reordered after any config change or package reload. This is particularly annoying when running pfBlockerNG — every cron run can silently shuffle your carefully ordered rules, breaking your security policy without any warning.

This has been discussed extensively on the Netgate forum since at least 2015:
- [pfBlockerNG rules going downwards in the firewall rule everyday](https://forum.netgate.com/topic/89551/pfblockerng-rules-is-going-downwards-in-the-firewall-rule-everyday) (22.5k views)
- [Feature request: Allow manual ordering of generated rules](https://redmine.pfsense.org/issues/15218)

There's no built-in fix. This script is my workaround.

---

## How it works

Add a numeric prefix to your rule descriptions directly in the pfSense GUI:

```
01 | Zoom UDP
02 | Zoom TCP
03 | Block IoT from accessing internal LAN
04 | Allow LAN to Whitelisted Internal Services
```

A cron job runs the script every few minutes. Here's what happens each run:

1. Reads `/cf/conf/config.xml`
2. Groups rules by interface (LAN, WAN, opt1, etc.)
3. Any rule without a prefix gets one assigned based on its current position
4. Rules are sorted by their prefix number within each interface
5. If anything changed — backs up `config.xml` first, then writes the updated version
6. Reloads the firewall filter (same as clicking Apply Changes in the GUI)
7. If everything was already in order — does nothing

pfBlockerNG auto rules (`pfB_*`), Floating rules, and Tailscale rules are never touched — they stay exactly where they are.

The first time you run it, prefix numbers get assigned to all your existing rules based on their current order. After that, if a rule gets moved by pfSense or any package, the script puts it back within 5 minutes.

---

## Requirements

- pfSense CE 2.7.x
- Python 3.x — check with: `ls /usr/local/bin/python3*`
- Run as root

---

## Setup

### 1. Copy the script to pfSense

```bash
cp pfsense_rule_order.py /root/Scripts/
```

### 2. Edit the configuration section at the top of the script

```python
CONFIG_XML          = "/cf/conf/config.xml"
BACKUP_DIR          = "/cf/conf/rule_order_backups"
LOG_FILE            = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS         = 10
DRY_RUN             = False
APPLY_RULES         = True

# Interfaces to manage (internal pfSense names)
# wan, lan, opt1 = first optional interface (LAN30), opt2, etc.
MANAGED_INTERFACES  = ["wan", "lan", "opt1"]

# Optional webhook notification (Gotify, ntfy, etc.)
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL          = ""
```

### 3. Get your Python binary name

```bash
ls /usr/local/bin/python3*
```

### 4. Do a dry run first

Make sure your rules are in the correct order in the GUI, then:

```bash
python3 /root/Scripts/pfsense_rule_order.py --dry-run
```

Check the output — it shows exactly what prefixes will be added and in what order. If something looks wrong, fix the rule order in the GUI first before running for real.

### 5. Run it

```bash
python3 /root/Scripts/pfsense_rule_order.py
```

### 6. Add to cron

In the pfSense GUI: **Services > Cron > Add**

| Field | Value |
|-------|-------|
| Minute | `*/5` |
| Hour | `*` |
| Day | `*` |
| Month | `*` |
| Weekday | `*` |
| User | `root` |
| Command | `python3 /root/Scripts/pfsense_rule_order.py` |

> If `python3` isn't found, use the full path from step 3 (e.g. `python3.11`)

---

## Numbering tips

- Two-digit numbers work best: `01`, `02`, `03` — single digits sort correctly too
- Leave gaps if you add rules often: `10`, `20`, `30`
- The last block rule on each interface should always have the highest number
- pfBlockerNG rules, Floating rules, and Tailscale rules don't need a prefix

---

## Example output

First run (adds prefixes):
```
2026-06-03 06:36:35 [INFO] === pfsense-rule-order v1.0.0 ===
2026-06-03 06:36:35 [INFO] [LAN] Prefix added: 'Block IoT' -> '03 | Block IoT'
2026-06-03 06:36:35 [INFO] [LAN] Prefix added: 'Allow LAN to Internet' -> '11 | Allow LAN to Internet'
2026-06-03 06:36:35 [INFO] Backup saved: /cf/conf/rule_order_backups/config_20260603_063635.xml
2026-06-03 06:36:35 [INFO] config.xml updated successfully.
2026-06-03 06:36:35 [INFO] Filter reloaded successfully.
2026-06-03 06:36:35 [INFO] === Done ===
```

Subsequent runs when order is already correct:
```
2026-06-03 06:42:09 [INFO] [WAN] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] [LAN] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] [OPT1] Already correct, nothing to do.
2026-06-03 06:42:09 [INFO] All interfaces already correct. Nothing to do.
```

---

## License

MIT

---

## ❤️ Support

If my projects helped you or saved you time, consider supporting future development:

👉 https://paypal.me/ShopNGF
