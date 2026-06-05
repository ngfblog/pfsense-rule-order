# pfsense-rule-order

Keeps your pfSense firewall rules in the right order, automatically.

> Tested on pfSense CE 2.7.2 and 2.8.1. Make a backup before using. Read the code before running anything from the internet.

---

## The problem

pfSense always adds new rules to the bottom of the list. Every time you add a rule and forget to drag it into position, your security policy silently breaks.

It gets worse when packages like pfBlockerNG are installed — they rewrite rules in config.xml periodically, which can shift your manually ordered rules without warning. But even without extra packages, the base problem is the same: pfSense has no way to lock rule order. This has come up many times on the Netgate forum with no built-in fix:

- [pfBlockerNG rules going downwards in the firewall rule everyday](https://forum.netgate.com/topic/89551/pfblockerng-rules-is-going-downwards-in-the-firewall-rule-everyday) (22k views)
- [How to make rules order persistent?](https://forum.netgate.com/topic/117911/how-to-make-rules-order-persistent)
- [Firewall Rules Order](https://forum.netgate.com/topic/125250/firewall-rules-order)
- [Rules order randomly changes](https://forum.netgate.com/topic/196601/rules-order-randomly-changes)

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

A cron job runs the script every hour (or however often you want). Each run does this:

1. Reads `/cf/conf/config.xml`
2. Auto-discovers all interfaces with manual rules (no configuration needed)
3. Rules without a prefix get numbered based on their current position — pushing subsequent rules +1
4. Sorts rules by their number within each interface
5. If anything changed — backs up `config.xml`, writes the updated version, clears the config cache, and reloads the firewall filter
6. If nothing changed — exits without touching anything

**What the script never touches:**

- **pfBlockerNG auto rules** — identified by `pfB_` at the start of the description. pfBlockerNG manages these itself, touching their position would conflict with it.
- **Floating rules** — identified by `<floating>yes</floating>` in the XML. These have their own evaluation context.
- **Tailscale rules** — identified by `interface = tailscale` in the XML. Same reason.

If your setup has other rules that should never be moved, open an issue and I'll add them.

---

## Requirements

- pfSense CE 2.7.x or 2.8.x
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
CONFIG_XML      = "/cf/conf/config.xml"
BACKUP_DIR      = "/cf/conf/rule_order_backups"
LOG_FILE        = "/var/log/pfsense_rule_order.log"
MAX_BACKUPS     = 10
DRY_RUN         = False
APPLY_RULES     = True

# Interfaces to always exclude (in addition to Floating and pfB_* rules)
EXCLUDED_INTERFACES = ["tailscale"]

# Optional Gotify / ntfy / webhook notification
# Example: "http://10.0.0.1:8070/message?token=YOURTOKEN"
NOTIFY_URL      = ""
```

No need to list your interfaces manually — the script discovers them automatically from `config.xml`.

**3. Check your Python binary name**

```bash
ls /usr/local/bin/python3*
```

**4. Dry run first**

Get your rules in the right order in the GUI first, then:

```bash
python3 /root/Scripts/pfsense_rule_order.py --dry-run
```

Check the output. If something looks wrong, fix the rule order in the GUI before running for real.

**5. Run it**

```bash
python3 /root/Scripts/pfsense_rule_order.py
```

**6. Add to cron**

Services > Cron > Add:

| Field | Value |
|-------|-------|
| Minute | `0` |
| Hour | `*` |
| Day | `*` |
| Month | `*` |
| Weekday | `*` |
| User | `root` |
| Command | `python3 /root/Scripts/pfsense_rule_order.py` |

If `python3` isn't found, use the full path from step 3 (e.g. `python3.11`).

---

## Numbering tips

- Two-digit numbers look cleaner: `01`, `02`, `03`
- If you add rules often, leave gaps: `10`, `20`, `30`
- The last blocking rule on each interface should always have the highest number
- pfBlockerNG, Floating, and Tailscale rules don't need a number — they're never touched

---

## Example output

First run (numbering applied):
```
2026-06-05 14:49:23 [INFO] === pfsense-rule-order v1.6.0 ===
2026-06-05 14:49:23 [INFO] Discovered interfaces: LAN, LAN30_VLAN, WAN
2026-06-05 14:49:23 [INFO] [LAN30_VLAN] Renumbered: 'Allow LAN to WebUI' -> '03 | Allow LAN to WebUI'
2026-06-05 14:49:23 [INFO] [LAN30_VLAN] Renumbered: '03 | Block firewall' -> '04 | Block firewall'
2026-06-05 14:49:23 [INFO] Backup saved: /cf/conf/rule_order_backups/config_20260605_144923.xml
2026-06-05 14:49:23 [INFO] Config cache cleared.
2026-06-05 14:49:23 [INFO] config.xml updated successfully.
2026-06-05 14:49:23 [INFO] Filter reloaded successfully.
2026-06-05 14:49:23 [INFO] === Done ===
```

When everything is already in order:
```
2026-06-05 15:10:15 [INFO] Discovered interfaces: LAN, LAN30_VLAN, WAN
2026-06-05 15:10:15 [INFO] [WAN] Already correct, nothing to do.
2026-06-05 15:10:15 [INFO] [LAN] Already correct, nothing to do.
2026-06-05 15:10:15 [INFO] [LAN30_VLAN] Already correct, nothing to do.
2026-06-05 15:10:15 [INFO] All interfaces already correct. Nothing to do.
```

---

## License

MIT

---

## ❤️ Support

If my projects helped you or saved you time, consider supporting future development:

👉 https://paypal.me/ShopNGF
