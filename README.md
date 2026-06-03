# pfsense-rule-order

Keeps your pfSense firewall rules in the right order, automatically.

> The scripts have been tested on pfSense CE 2.7.2. Make a backup before using. As always, read the code before running anything from the internet.

---

## The problem

pfSense always adds new rules to the bottom of the list. Every time you add a rule, you have to manually drag it to the right position. Miss it once, and your security policy silently breaks.

It gets worse if you're running pfBlockerNG — its cron job rewrites firewall rules periodically, and your carefully ordered rules can get shuffled without any warning. This has been [reported on the Netgate forum since at least 2015](https://forum.netgate.com/topic/89551/pfblockerng-rules-is-going-downwards-in-the-firewall-rule-everyday) (22k+ views) and there's a [feature request open since 2023](https://redmine.pfsense.org/issues/15218) asking for manual rule ordering. Still no built-in fix.

This script is my workaround.

---

## How it works

Add a number to the start of any rule description in the pfSense GUI:

```
01 | Zoom UDP
02 | Zoom TCP
03 | Block IoT from accessing internal LAN
04 | Allow LAN to Whitelisted Internal Services
```

A cron job runs the script every few minutes. Each run does this:

1. Reads `/cf/conf/config.xml`
2. Groups rules by interface
3. Rules without a prefix get a number assigned based on their current position — this only happens once, on first run
4. Sorts rules by their number within each interface
5. If the order changed — backs up `config.xml`, then writes the updated version
6. Reloads the firewall filter (same as clicking Apply Changes in the GUI)
7. If nothing changed — exits immediately without touching anything

**What the script never touches:**

- **pfBlockerNG auto rules** — identified by `pfB_` at the start of the description. These are managed by pfBlockerNG and messing with their position would conflict with its cron job.
- **Floating rules** — identified by `<floating>yes</floating>` in the XML. These live in a separate tab and have their own evaluation order.
- **Tailscale rules** — identified by `interface = tailscale` in the XML. Same reason as floating — separate context, leave them alone.

Everything else on WAN, LAN, and opt interfaces gets a number and stays in order.

---

## Requirements

- pfSense CE 2.7.x
- Python 3.x — check with: `ls /usr/local/bin/python3*`
- Run as root

---

## Setup

**1. Copy the script**

```bash
cp pfsense_rule_order.py /root/Scripts/
```

**2. Edit the configuration at the top of the script**

```python
CONFIG_XML          = "/cf/conf/config.xml"
BACKUP_DIR          = "/cf/conf/rule_order_backups"
LOG_FILE            = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS         = 10
DRY_RUN             = False
APPLY_RULES         = True

# Internal pfSense interface names: wan, lan, opt1 (first extra interface), opt2, etc.
MANAGED_INTERFACES  = ["wan", "lan", "opt1"]

# Optional Gotify / ntfy / webhook notification
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL          = ""
```

**3. Check your Python binary name**

```bash
ls /usr/local/bin/python3*
```

**4. Dry run first**

Get your rules in the right order in the GUI, then:

```bash
python3 /root/Scripts/pfsense_rule_order.py --dry-run
```

Check the output before continuing. If something looks wrong, fix the rule order in the GUI first.

**5. Run it**

```bash
python3 /root/Scripts/pfsense_rule_order.py
```

**6. Add to cron**

Services > Cron > Add:

| Field | Value |
|-------|-------|
| Minute | `*/5` |
| Hour | `*` |
| Day | `*` |
| Month | `*` |
| Weekday | `*` |
| User | `root` |
| Command | `python3 /root/Scripts/pfsense_rule_order.py` |

If `python3` isn't found, use the full path from step 3 (e.g. `python3.11`).

---

## Numbering tips

- Two-digit numbers: `01`, `02` — single digits work too but two-digit looks cleaner
- Leave gaps if you add rules often: `10`, `20`, `30`
- The last blocking rule on each interface should always have the highest number
- pfBlockerNG, Floating, and Tailscale rules don't need a number

---

## Example output

First run:
```
2026-06-03 06:36:35 [INFO] === pfsense-rule-order v1.0.0 ===
2026-06-03 06:36:35 [INFO] [LAN] Prefix added: 'Block IoT' -> '03 | Block IoT'
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
