"""Servidor mock de um UDM Pro (Integration API + API classica) para testes locais.

Uso: python -m tests.mock_udm  (porta 8443, HTTP)
Depois: UNIFI_HOST=127.0.0.1:8443 UNIFI_API_KEY=test-key-1234567890 uvicorn app.main:app
"""
from __future__ import annotations

import time
import uuid

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request

API_KEY = "test-key-1234567890"
SITE = str(uuid.uuid4())
NOW = int(time.time() * 1000)
mock = FastAPI()

ZONES = {n: str(uuid.uuid4()) for n in ["Internal", "External", "Guest", "VPN", "Hotspot", "DMZ"]}
NETS = {
    "Default": {"id": str(uuid.uuid4()), "vlanId": 1, "default": True, "isolationEnabled": False, "dhcpGuarding": None, "zone": "Internal", "dns": [], "cf": "NONE"},
    # Corp reproduz o problema real: DNS apontado para dois controladores de dominio
    # internos E content filtering ligado -> o PREROUTING sequestra a porta 53 e o AD quebra.
    "Corp": {"id": str(uuid.uuid4()), "vlanId": 10, "default": False, "isolationEnabled": False, "dhcpGuarding": None, "zone": "Internal",
             "dns": ["192.168.10.10", "192.168.10.11"], "cf": "WORK"},
    "IoT": {"id": str(uuid.uuid4()), "vlanId": 20, "default": False, "isolationEnabled": False, "dhcpGuarding": None, "zone": "Internal", "dns": [], "cf": "NONE"},
    # Guest tem filtro ligado mas nenhum DNS interno: filtrar aqui e correto, nao e conflito.
    "Guest": {"id": str(uuid.uuid4()), "vlanId": 30, "default": False, "isolationEnabled": True, "dhcpGuarding": {"enabled": True}, "zone": "Guest", "dns": [], "cf": "FAMILY"},
}
WANS = [
    {"id": "w1", "name": "WAN1", "enabled": True, "active": True, "state": "UP", "failoverPriority": 1, "ipv4": {"type": "DHCP", "ipAddress": "203.0.113.5"}},
    {"id": "w2", "name": "WAN2", "enabled": True, "active": False, "state": "STANDBY", "failoverPriority": 2, "ipv4": {"type": "DHCP", "ipAddress": "198.51.100.7"}},
]
# Na API classica os servidores VPN aparecem como networkconf e sao gravaveis.
NETWORKCONF = [
    {"_id": "nc-vpn-1", "name": "WireGuard Casa", "purpose": "vpn-server", "vpn_type": "wireguard", "wan": "w1", "enabled": True, "x_wg_private_key": "REDACTED"},
    {"_id": "nc-vpn-2", "name": "Legado", "purpose": "vpn-server", "vpn_type": "pptp", "wan": "w1", "enabled": True},
]
GW_ID, AP_ID, SW_ID = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
DEVICES = [
    {"id": GW_ID, "name": "UDM Pro", "model": "UDMPRO", "macAddress": "aa:bb:cc:00:00:01", "ipAddress": "192.168.1.1", "state": "ONLINE", "firmwareVersion": "4.1.13", "firmwareUpdatable": True, "features": ["gateway", "switching"], "interfaces": ["ports"]},
    {"id": AP_ID, "name": "AP Sala", "model": "U6LR", "macAddress": "aa:bb:cc:00:00:02", "ipAddress": "192.168.1.10", "state": "ONLINE", "firmwareVersion": "6.6.55", "firmwareUpdatable": False, "features": ["accessPoint"], "interfaces": ["radios", "ports"]},
    {"id": SW_ID, "name": "Switch Escritorio", "model": "USL8LP", "macAddress": "aa:bb:cc:00:00:03", "ipAddress": "192.168.1.11", "state": "OFFLINE", "firmwareVersion": "7.0.50", "firmwareUpdatable": False, "features": ["switching"], "interfaces": ["ports"]},
]
CLIENTS = [
    {"id": str(uuid.uuid4()), "name": "PC-Joao", "type": "WIRED", "macAddress": "11:22:33:44:55:01", "ipAddress": "192.168.1.50", "connectedAt": "2026-09-12T10:00:00Z", "access": {"type": "DEFAULT"}, "uplinkDeviceId": SW_ID},
    {"id": str(uuid.uuid4()), "name": "Camera-Quintal", "type": "WIRELESS", "macAddress": "11:22:33:44:55:02", "ipAddress": "192.168.20.15", "connectedAt": "2026-09-10T08:00:00Z", "access": {"type": "DEFAULT"}, "uplinkDeviceId": AP_ID},
    {"id": str(uuid.uuid4()), "name": "iPhone", "type": "WIRELESS", "macAddress": "11:22:33:44:55:03", "ipAddress": "192.168.1.77", "connectedAt": "2026-09-13T01:00:00Z", "access": {"type": "GUEST"}, "uplinkDeviceId": AP_ID},
]
WIFI = [
    {"id": str(uuid.uuid4()), "name": "Casa", "enabled": True, "type": "STANDARD", "securityConfiguration": {"type": "WPA2_WPA3_PERSONAL", "passphrase": "senha-super-segura-123", "pmfMode": "OPTIONAL"}, "network": {"type": "SPECIFIC", "networkId": NETS["Default"]["id"]}, "broadcastingFrequenciesGHz": [2.4, 5], "clientIsolationEnabled": False, "hideName": False},
    {"id": str(uuid.uuid4()), "name": "IoT", "enabled": True, "type": "STANDARD", "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "iot1234", "pmfMode": "DISABLED"}, "network": {"type": "SPECIFIC", "networkId": NETS["IoT"]["id"]}, "broadcastingFrequenciesGHz": [2.4], "clientIsolationEnabled": False, "hideName": False},
    {"id": str(uuid.uuid4()), "name": "Visitantes", "enabled": True, "type": "STANDARD", "securityConfiguration": {"type": "OPEN"}, "network": {"type": "SPECIFIC", "networkId": NETS["Guest"]["id"]}, "broadcastingFrequenciesGHz": [2.4, 5], "clientIsolationEnabled": False, "hideName": False},
]
POLICIES = [
    {"id": str(uuid.uuid4()), "name": "Allow Internal to External", "enabled": True, "loggingEnabled": False, "index": 10000, "action": {"type": "ALLOW"}, "source": {"zoneId": ZONES["Internal"]}, "destination": {"zoneId": ZONES["External"]}, "ipProtocolScope": {"ipVersion": "BOTH"}, "metadata": {"origin": "PREDEFINED"}},
    {"id": str(uuid.uuid4()), "name": "Permitir tudo Guest->Internal", "enabled": True, "loggingEnabled": False, "index": 20000, "action": {"type": "ALLOW"}, "source": {"zoneId": ZONES["Guest"]}, "destination": {"zoneId": ZONES["Internal"]}, "ipProtocolScope": {"ipVersion": "BOTH"}, "metadata": {"origin": "USER_DEFINED"}},
    {"id": str(uuid.uuid4()), "name": "Allow External to Internal", "enabled": True, "loggingEnabled": False, "index": 20001, "action": {"type": "ALLOW"}, "source": {"zoneId": ZONES["External"]}, "destination": {"zoneId": ZONES["Internal"]}, "ipProtocolScope": {"ipVersion": "BOTH"}, "metadata": {"origin": "USER_DEFINED"}},
]
SETTINGS = [
    {"key": "ips", "ips_mode": "ids", "enabled_categories": ["emerging-malware"], "ad_blocking_enabled": False, "restrict_tor": False, "restrict_torrents": False, "honeypot_enabled": False, "_id": "s1", "site_id": "default"},
    {"key": "usg", "upnp_enabled": True, "geo_ip_filtering_enabled": False, "firewall_wan_default_log": False, "firewall_lan_default_log": False, "mdns_enabled": True, "_id": "s2", "site_id": "default"},
    {"key": "mgmt", "x_ssh_enabled": True, "auto_upgrade": False, "led_enabled": True, "_id": "s3", "site_id": "default"},
    {"key": "dpi", "enabled": True, "_id": "s4", "site_id": "default"},
]
IPS_EVENTS = [
    {"time": NOW - 3600_000, "inner_alert_signature": "ET MALWARE Win32/Emotet CnC Beacon", "inner_alert_category": "A Network Trojan was detected", "inner_alert_severity": 1, "inner_alert_action": "allowed", "src_ip": "192.168.20.15", "dest_ip": "45.33.12.9", "src_port": 51234, "dest_port": 443, "proto": "TCP", "app_proto": "tls", "dstipCountry": "RU", "catname": "emerging-malware", "inner_alert_signature_id": 2027001},
    {"time": NOW - 7200_000, "inner_alert_signature": "ET SCAN Potential SSH Scan", "inner_alert_category": "Attempted Information Leak", "inner_alert_severity": 2, "inner_alert_action": "blocked", "src_ip": "185.220.101.5", "dest_ip": "203.0.113.5", "src_port": 40000, "dest_port": 22, "proto": "TCP", "srcipCountry": "DE", "catname": "emerging-scan", "inner_alert_signature_id": 2001219},
    {"time": NOW - 9000_000, "inner_alert_signature": "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)", "inner_alert_category": "Attempted Administrator Privilege Gain", "inner_alert_severity": 1, "inner_alert_action": "blocked", "src_ip": "5.188.86.1", "dest_ip": "203.0.113.5", "src_port": 55555, "dest_port": 8080, "proto": "TCP", "app_proto": "http", "srcipCountry": "NL", "catname": "emerging-exploit"},
    {"time": NOW - 20000_000, "inner_alert_signature": "ET POLICY TOR Relay Traffic", "inner_alert_category": "Potential Corporate Privacy Violation", "inner_alert_severity": 3, "inner_alert_action": "allowed", "src_ip": "192.168.1.50", "dest_ip": "199.58.81.140", "src_port": 60001, "dest_port": 9001, "proto": "TCP", "dstipCountry": "US", "catname": "emerging-tor"},
    {"time": NOW - 30000_000, "inner_alert_signature": "ET DROP Dshield Block Listed Source group 1", "inner_alert_category": "Misc Attack", "inner_alert_severity": 2, "inner_alert_action": "blocked", "src_ip": "80.82.77.139", "dest_ip": "203.0.113.5", "src_port": 51000, "dest_port": 3389, "proto": "TCP", "srcipCountry": "NL", "catname": "emerging-dshield"},
] * 3
EVENTS = [
    {"time": NOW - 600_000, "key": "EVT_WU_Connected", "msg": "User[11:22:33:44:55:03] has connected to AP[aa:bb:cc:00:00:02] with SSID \"Casa\"", "user": "11:22:33:44:55:03", "ssid": "Casa", "ap_name": "AP Sala"},
    {"time": NOW - 1200_000, "key": "EVT_AD_Login", "msg": "Admin[admin] logged in from 203.0.113.99", "admin": "admin", "ip": "203.0.113.99"},
    {"time": NOW - 1800_000, "key": "EVT_SW_Lost_Contact", "msg": "Switch[aa:bb:cc:00:00:03] was disconnected", "sw_name": "Switch Escritorio"},
    {"time": NOW - 3000_000, "key": "EVT_IPS_IpsAlert", "msg": "IPS Alert 1: A Network Trojan was detected", "src_ip": "192.168.20.15"},
    {"time": NOW - 5000_000, "key": "EVT_WU_RoguAPDetected", "msg": "Rogue AP detected", "ap_name": "AP Sala"},
]
ALARMS = [
    {"time": NOW - 1800_000, "key": "EVT_SW_Lost_Contact", "msg": "Switch[Switch Escritorio] was disconnected", "archived": False},
    {"time": NOW - 900_000, "key": "EVT_GW_WANTransition", "msg": "WAN failover", "archived": True},
]


def auth(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(401, {"statusCode": 401, "message": "Unauthorized"})


def page(items):
    return {"offset": 0, "limit": len(items), "count": len(items), "totalCount": len(items), "data": items}


I = "/proxy/network/integration/v1"
C = "/proxy/network/api/s/default"


@mock.get(I + "/info")
def info(x_api_key: str | None = Header(None)):
    auth(x_api_key); return {"applicationVersion": "10.4.57"}


@mock.get(I + "/sites")
def sites(x_api_key: str | None = Header(None)):
    auth(x_api_key); return page([{"id": SITE, "internalReference": "default", "name": "Casa"}])


@mock.get(I + "/pending-devices")
def pending(x_api_key: str | None = Header(None)):
    auth(x_api_key); return page([{"model": "U6-Lite", "macAddress": "aa:bb:cc:00:00:99", "ipAddress": "192.168.1.200"}])


@mock.get(I + "/sites/{s}/devices")
def devices(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page(DEVICES)


@mock.get(I + "/sites/{s}/devices/{d}")
def device(s: str, d: str, x_api_key: str | None = Header(None)):
    auth(x_api_key)
    dev = next((x for x in DEVICES if x["id"] == d), None) or _404()
    return {**dev, "adoptedAt": "2025-01-01T00:00:00Z", "provisionedAt": "2026-09-01T00:00:00Z",
            "interfaces": {"ports": [{"idx": i, "connector": "RJ45", "state": "UP" if i < 5 else "DOWN", "speedMbps": 1000, "maxSpeedMbps": 1000, "poe": {"enabled": True, "standard": "802.3af", "state": "UP"}} for i in range(1, 9)],
                           "radios": [{"frequencyGHz": 2.4, "channel": 6, "channelWidthMHz": 20, "wlanStandard": "802.11ax"}, {"frequencyGHz": 5, "channel": 44, "channelWidthMHz": 80, "wlanStandard": "802.11ax"}]}}


@mock.get(I + "/sites/{s}/devices/{d}/statistics/latest")
def dstats(s: str, d: str, x_api_key: str | None = Header(None)):
    auth(x_api_key)
    return {"uptimeSec": 864000, "lastHeartbeatAt": "2026-09-13T01:59:00Z", "cpuUtilizationPct": 23.5, "memoryUtilizationPct": 61.0, "loadAverage1Min": 0.5, "loadAverage5Min": 0.6, "loadAverage15Min": 0.4,
            "uplink": {"txRateBps": 1_200_000, "rxRateBps": 25_000_000}, "interfaces": {"radios": [{"frequencyGHz": 2.4, "connectedClients": 3, "utilizationPct": 12}], "ports": [{"portIdx": 1, "rxRateBps": 1000, "txRateBps": 2000}]}}


@mock.post(I + "/sites/{s}/devices/{d}/actions")
async def daction(s: str, d: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); return {}


@mock.get(I + "/sites/{s}/clients")
def clients(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page(CLIENTS)


def _net(n, name):
    return {"id": n["id"], "name": name, "enabled": True, "management": "GATEWAY", "vlanId": n["vlanId"], "default": n["default"], "zoneId": ZONES[n["zone"]],
            "isolationEnabled": n["isolationEnabled"], "internetAccessEnabled": True, "mdnsForwardingEnabled": True, "dhcpGuarding": n["dhcpGuarding"],
            "contentFilteringLevel": n["cf"],
            "ipv4Configuration": {"hostIpAddress": f"192.168.{n['vlanId']}.1", "prefixLength": 24,
                                  "dhcpConfiguration": {"mode": "SERVER", "dnsServers": n["dns"], "range": {"start": f"192.168.{n['vlanId']}.6", "stop": f"192.168.{n['vlanId']}.254"}}}}


@mock.get(I + "/sites/{s}/networks")
def networks(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page([_net(n, k) for k, n in NETS.items()])


@mock.get(I + "/sites/{s}/networks/{nid}")
def network(s: str, nid: str, x_api_key: str | None = Header(None)):
    auth(x_api_key)
    for k, n in NETS.items():
        if n["id"] == nid:
            return _net(n, k)
    _404()


@mock.put(I + "/sites/{s}/networks/{nid}")
async def upd_network(s: str, nid: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for n in NETS.values():
        if n["id"] == nid:
            n["isolationEnabled"] = body.get("isolationEnabled", n["isolationEnabled"]); n["dhcpGuarding"] = body.get("dhcpGuarding", n["dhcpGuarding"])
            if "contentFilteringLevel" in body:
                n["cf"] = body["contentFilteringLevel"] or "NONE"
    return body


@mock.get(I + "/sites/{s}/wifi/broadcasts")
def wifi(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page([{k: v for k, v in w.items() if k in ("id", "name", "enabled", "type")} for w in WIFI])


@mock.get(I + "/sites/{s}/wifi/broadcasts/{w}")
def wifi_d(s: str, w: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return next((x for x in WIFI if x["id"] == w), None) or _404()


@mock.put(I + "/sites/{s}/wifi/broadcasts/{w}")
async def wifi_u(s: str, w: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for x in WIFI:
        if x["id"] == w:
            x.update(body)
    return body


@mock.get(I + "/sites/{s}/firewall/zones")
def zones(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page([{"id": i, "name": n, "networkIds": [x["id"] for x in NETS.values() if x["zone"] == n], "metadata": {"origin": "PREDEFINED"}} for n, i in ZONES.items()])


@mock.get(I + "/sites/{s}/firewall/policies")
def policies(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page(POLICIES)


@mock.post(I + "/sites/{s}/firewall/policies")
async def add_policy(s: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json(); body["id"] = str(uuid.uuid4()); body["index"] = 20002; body["metadata"] = {"origin": "USER_DEFINED"}; POLICIES.append(body); return body


# Precisa vir antes de /policies/{p}, senao "ordering" e capturado como id de politica.
@mock.get(I + "/sites/{s}/firewall/policies/ordering")
def get_ordering(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key)
    return {"firewallPolicyIds": [p["id"] for p in POLICIES if p.get("metadata", {}).get("origin") == "USER_DEFINED"]}


@mock.put(I + "/sites/{s}/firewall/policies/ordering")
async def put_ordering(s: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    ids = body.get("firewallPolicyIds", [])
    rank = {pid: i for i, pid in enumerate(ids)}
    POLICIES.sort(key=lambda p: rank.get(p["id"], 999))
    for p in POLICIES:
        if p["id"] in rank:
            p["index"] = 20000 + rank[p["id"]]
    return {"firewallPolicyIds": ids}


@mock.get(I + "/sites/{s}/firewall/policies/{p}")
def get_policy(s: str, p: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return next((x for x in POLICIES if x["id"] == p), None) or _404()


@mock.put(I + "/sites/{s}/firewall/policies/{p}")
async def put_policy(s: str, p: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for x in POLICIES:
        if x["id"] == p:
            x.update(body)
    return body


@mock.patch(I + "/sites/{s}/firewall/policies/{p}")
async def patch_policy(s: str, p: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for x in POLICIES:
        if x["id"] == p:
            x["loggingEnabled"] = body.get("loggingEnabled", x["loggingEnabled"])
    return body


@mock.delete(I + "/sites/{s}/firewall/policies/{p}")
def del_policy(s: str, p: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); POLICIES[:] = [x for x in POLICIES if x["id"] != p]; return {}


@mock.get(I + "/sites/{s}/vpn/servers")
def vpn(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key)
    return page([{"id": "v1", "name": "WireGuard Casa", "type": "WIREGUARD", "enabled": True},
                 {"id": "v2", "name": "Legado", "type": "PPTP", "enabled": True}])


@mock.get(I + "/sites/{s}/wans")
def wans(s: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return page(WANS)


@mock.post("/_sim/failover")
def sim_failover():
    """Helper apenas do mock: promove a WAN em espera, como num failover real."""
    cur = next((w for w in WANS if w["active"]), WANS[0])
    nxt = next((w for w in WANS if w["id"] != cur["id"] and w["enabled"]), None)
    if not nxt:
        return {"ok": False, "message": "Nenhuma WAN alternativa."}
    cur["active"], cur["state"] = False, "STANDBY"
    nxt["active"], nxt["state"] = True, "UP"
    return {"ok": True, "from": cur["name"], "to": nxt["name"], "activeWanIp": nxt["ipv4"]["ipAddress"]}


for path in ["/sites/{s}/acl-rules", "/sites/{s}/dns/policies", "/sites/{s}/vpn/site-to-site-tunnels", "/sites/{s}/traffic-matching-lists", "/sites/{s}/hotspot/vouchers", "/sites/{s}/dpi/categories"]:
    def _mk(path=path):
        def h(s: str, x_api_key: str | None = Header(None)):
            auth(x_api_key); return page([])
        return h
    mock.add_api_route(I + path, _mk(), methods=["GET"])


def _404():
    raise HTTPException(404, {"statusCode": 404, "message": "Not found"})


# --------------------------------------------------------- API classica
def cwrap(data):
    return {"meta": {"rc": "ok"}, "data": data}


@mock.get(C + "/stat/health")
def health(x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap([{"subsystem": "wan", "status": "ok"}, {"subsystem": "lan", "status": "ok"}, {"subsystem": "wlan", "status": "warning"}, {"subsystem": "www", "status": "ok"}, {"subsystem": "vpn", "status": "ok"}])


@mock.get(C + "/stat/sysinfo")
def sysinfo(x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap([{"version": "10.4.57", "hostname": "udm-pro", "ubnt_device_type": "UDMPRO"}])


@mock.get(C + "/stat/event")
@mock.post(C + "/stat/event")
async def events(req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap(EVENTS)


@mock.get(C + "/stat/alarm")
@mock.post(C + "/stat/alarm")
async def alarms(req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap(ALARMS)


@mock.get(C + "/stat/ips/event")
@mock.post(C + "/stat/ips/event")
async def ips(req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap(IPS_EVENTS)


@mock.get(C + "/stat/sta")
def sta(x_api_key: str | None = Header(None)):
    auth(x_api_key)
    return cwrap([{"mac": c["macAddress"], "oui": "Apple" if "iPhone" in c["name"] else "Hikvision" if "Camera" in c["name"] else "Dell", "hostname": c["name"].lower(), "rx_bytes": 123456789, "tx_bytes": 9876543, "signal": -55, "essid": "Casa", "network": "Default", "blocked": False, "is_guest": c["access"]["type"] == "GUEST"} for c in CLIENTS])


@mock.get(C + "/stat/device")
def cdev(x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap([{"mac": d["macAddress"], "name": d["name"], "upgradable": d["firmwareUpdatable"]} for d in DEVICES])


@mock.get(C + "/get/setting")
@mock.get(C + "/rest/setting")
def settings(x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap(SETTINGS)


@mock.get(C + "/rest/setting/{key}")
def setting(key: str, x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap([s for s in SETTINGS if s["key"] == key])


@mock.put(C + "/rest/setting/{key}")
@mock.put(C + "/rest/setting/{key}/{sid}")
@mock.post(C + "/set/setting/{key}")
@mock.put(C + "/set/setting/{key}")
async def set_setting(key: str, req: Request, sid: str | None = None, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for s in SETTINGS:
        if s["key"] == key:
            s.update(body)
    return cwrap([body])


@mock.post(C + "/cmd/stamgr")
async def stamgr(req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap([await req.json()])


@mock.get(C + "/rest/networkconf")
def networkconf(x_api_key: str | None = Header(None)):
    auth(x_api_key); return cwrap(NETWORKCONF)


@mock.put(C + "/rest/networkconf/{cid}")
async def upd_networkconf(cid: str, req: Request, x_api_key: str | None = Header(None)):
    auth(x_api_key); body = await req.json()
    for n in NETWORKCONF:
        if n["_id"] == cid:
            n.update({k: v for k, v in body.items() if k != "_id"})
            return cwrap([n])
    _404()


if __name__ == "__main__":
    uvicorn.run(mock, host="127.0.0.1", port=8443, log_level="warning")
