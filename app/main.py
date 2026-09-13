"""Painel UniFi de Seguranca - backend FastAPI."""
from __future__ import annotations

import contextlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .audit import SecurityAudit, apply_fix, build_block_policy
from .orchestrator import (
    FailoverMonitor,
    apply_ad_dns_plan,
    apply_ad_dns_step,
    build_ad_dns_plan,
    plan_vpn_reconcile,
    reconcile_vpn,
    simulate_failover,
    wan_snapshot,
)
from .threats import ALARM_HINTS, explain_event, explain_system_event, summarize
from .unifi_client import UniFiClient, UniFiConfig, UniFiError

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
CONFIG_PATH = Path(os.environ.get("UNIFI_PANEL_CONFIG", Path.home() / ".unifi-panel" / "config.json"))

app = FastAPI(title="Painel UniFi de Seguranca", version="1.0.0")

_lock = threading.Lock()
_client: UniFiClient | None = None
_cfg: UniFiConfig | None = None


# ----------------------------------------------------------------- config
def load_config() -> UniFiConfig:
    global _cfg
    if _cfg:
        return _cfg
    data: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
        except ValueError:
            data = {}
    env = {
        "mode": os.environ.get("UNIFI_MODE"),
        "host": os.environ.get("UNIFI_HOST"),
        "console_id": os.environ.get("UNIFI_CONSOLE_ID"),
        "api_key": os.environ.get("UNIFI_API_KEY"),
        "site_id": os.environ.get("UNIFI_SITE_ID"),
    }
    for k, v in env.items():
        if v:
            data[k] = v
    if "verify_ssl" in data:
        data["verify_ssl"] = bool(data["verify_ssl"])
    allowed = {k: v for k, v in data.items() if k in UniFiConfig.__dataclass_fields__}
    _cfg = UniFiConfig(**allowed)
    return _cfg


def save_config(cfg: UniFiConfig):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg.__dict__, indent=2))
    with contextlib.suppress(OSError):
        os.chmod(CONFIG_PATH, 0o600)


def client() -> UniFiClient:
    global _client
    with _lock:
        if _client is None:
            cfg = load_config()
            if not cfg.is_configured():
                raise HTTPException(status_code=428, detail="Painel nao configurado. Informe host/console e chave API em Configuracoes.")
            _client = UniFiClient(cfg)
        return _client


def reset_client():
    global _client, _cfg
    with _lock:
        _client = None
        _cfg = None


@app.exception_handler(UniFiError)
async def unifi_error_handler(_, exc: UniFiError):
    return JSONResponse(status_code=502 if exc.status is None else exc.status if exc.status >= 400 else 502,
                        content={"detail": str(exc), "unifi": exc.detail, "status": exc.status})


def masked(cfg: UniFiConfig) -> dict:
    d = dict(cfg.__dict__)
    k = d.get("api_key") or ""
    d["api_key"] = (k[:4] + "…" + k[-4:]) if len(k) > 8 else ("•" * len(k))
    d["configured"] = cfg.is_configured()
    d["config_path"] = str(CONFIG_PATH)
    return d


@app.get("/api/config")
def get_config():
    return masked(load_config())


@app.post("/api/config")
def set_config(body: dict = Body(...)):
    cfg = load_config()
    new = UniFiConfig(
        mode=body.get("mode", cfg.mode) or "local",
        host=(body.get("host", cfg.host) or "").strip(),
        console_id=(body.get("console_id", cfg.console_id) or "").strip(),
        api_key=(body.get("api_key") or cfg.api_key).strip() if body.get("api_key") and "…" not in body.get("api_key") else cfg.api_key,
        site_id=(body.get("site_id", cfg.site_id) or "").strip(),
        verify_ssl=bool(body.get("verify_ssl", cfg.verify_ssl)),
        timeout=float(body.get("timeout", cfg.timeout) or 20),
    )
    save_config(new)
    reset_client()
    return masked(new)


@app.post("/api/config/test")
def test_config(body: dict | None = Body(None)):
    """Testa a conexao usando a config salva (ou a enviada, sem salvar)."""
    if body and body.get("api_key") and "…" not in body["api_key"]:
        cfg = UniFiConfig(mode=body.get("mode", "local"), host=body.get("host", ""), console_id=body.get("console_id", ""),
                          api_key=body["api_key"], site_id=body.get("site_id", ""), verify_ssl=bool(body.get("verify_ssl", False)))
        c = UniFiClient(cfg)
    else:
        c = client()
    return c.test_connection()


# --------------------------------------------------------------- overview
@app.get("/api/overview")
def overview():
    c = client()
    out: dict[str, Any] = {"errors": {}}

    def grab(name, fn):
        try:
            out[name] = fn()
        except UniFiError as e:
            out[name] = None
            out["errors"][name] = str(e)

    grab("info", c.info)
    grab("site", c.site)
    grab("devices", c.devices)
    grab("clients", c.clients)
    grab("networks", c.networks)
    grab("wifi", c.wifi)
    grab("wans", c.wans)
    grab("zones", c.firewall_zones)
    grab("policies", c.firewall_policies)
    grab("vpn", c.vpn_servers)
    grab("pending", c.pending_devices)
    out["classicApi"] = c.classic_available()
    if out["classicApi"]:
        grab("health", c.health)
        grab("sysinfo", c.sysinfo)
        try:
            evs = c.ips_events(500)
            by_ip = {cl["ipAddress"]: cl for cl in (out.get("clients") or []) if cl.get("ipAddress")}
            out["threats"] = summarize([explain_event(e, by_ip) for e in evs])
        except UniFiError as e:
            out["threats"] = None
            out["errors"]["threats"] = str(e)
        try:
            out["alarms"] = [explain_system_event(a) for a in c.alarms(50) if not a.get("archived")]
        except UniFiError as e:
            out["alarms"] = []
            out["errors"]["alarms"] = str(e)
    # stats de dispositivos (gateway primeiro)
    stats = {}
    for d in (out.get("devices") or [])[:12]:
        with contextlib.suppress(UniFiError):
            stats[d["id"]] = c.device_stats(d["id"])
    out["deviceStats"] = stats
    return out


# ----------------------------------------------------------- integration
@app.get("/api/sites")
def sites():
    return client().sites()


@app.get("/api/devices")
def devices(stats: bool = False):
    c = client()
    ds = c.devices()
    if stats:
        for d in ds:
            try:
                d["stats"] = c.device_stats(d["id"])
            except UniFiError:
                d["stats"] = None
    return ds


@app.get("/api/devices/{device_id}")
def device(device_id: str):
    c = client()
    d = c.device(device_id)
    try:
        d["stats"] = c.device_stats(device_id)
    except UniFiError:
        d["stats"] = None
    return d


@app.post("/api/devices/{device_id}/restart")
def device_restart(device_id: str):
    return {"ok": True, "result": client().device_action(device_id, "RESTART")}


@app.get("/api/pending-devices")
def pending():
    return client().pending_devices()


@app.get("/api/clients")
def clients():
    c = client()
    cl = c.clients()
    # enriquece com dados da API classica (fabricante, trafego, sinal, bloqueado) quando disponivel
    if c.classic_available():
        try:
            by_mac = {s.get("mac", "").lower(): s for s in c.classic_clients()}
            for x in cl:
                s = by_mac.get((x.get("macAddress") or "").lower())
                if s:
                    x["extra"] = {
                        "oui": s.get("oui"), "hostname": s.get("hostname"), "rxBytes": s.get("rx_bytes"), "txBytes": s.get("tx_bytes"),
                        "signal": s.get("signal"), "rssi": s.get("rssi"), "essid": s.get("essid"), "network": s.get("network"),
                        "channel": s.get("channel"), "radioProto": s.get("radio_proto"), "uptime": s.get("uptime"),
                        "blocked": s.get("blocked"), "isGuest": s.get("is_guest"), "vlan": s.get("vlan"),
                        "switchPort": s.get("sw_port"), "firstSeen": s.get("first_seen"), "lastSeen": s.get("last_seen"),
                        "deviceName": s.get("dev_cat") and s.get("dev_family"), "os": s.get("os_name"), "fingerprint": s.get("dev_id"),
                    }
        except UniFiError:
            pass
    return cl


@app.get("/api/clients/{client_id}")
def client_detail(client_id: str):
    return client().client(client_id)


@app.post("/api/clients/block")
def client_block(body: dict = Body(...)):
    return apply_fix(client(), "unblock_client" if body.get("unblock") else "block_client", {"mac": body["mac"]})


@app.get("/api/networks")
def networks(detail: bool = True):
    c = client()
    ns = c.networks()
    if detail:
        out = []
        for n in ns:
            try:
                out.append(c.network(n["id"]))
            except UniFiError:
                out.append(n)
        return out
    return ns


@app.get("/api/wifi")
def wifi(detail: bool = True):
    c = client()
    ws = c.wifi()
    if detail:
        out = []
        for w in ws:
            try:
                d = c.wifi_detail(w["id"])
                sec = d.get("securityConfiguration") or {}
                if "passphrase" in sec:
                    sec["passphraseLength"] = len(sec["passphrase"] or "")
                    sec["passphrase"] = "••••••••"
                out.append(d)
            except UniFiError:
                out.append(w)
        return out
    return ws


@app.get("/api/firewall")
def firewall():
    c = client()
    zones = c.firewall_zones()
    policies = c.firewall_policies()
    try:
        acl = c.acl_rules()
    except UniFiError:
        acl = []
    try:
        tml = c.traffic_lists()
    except UniFiError:
        tml = []
    return {"zones": zones, "policies": policies, "aclRules": acl, "trafficMatchingLists": tml}


@app.post("/api/firewall/policies")
def create_policy(body: dict = Body(...)):
    if body.get("preview"):
        return {"preview": build_block_policy(body)}
    return apply_fix(client(), "create_block_policy", body)


@app.post("/api/firewall/policies/{policy_id}/logging")
def policy_logging(policy_id: str, body: dict = Body(...)):
    return client().patch_firewall_policy(policy_id, {"loggingEnabled": bool(body.get("enabled", True))})


@app.post("/api/firewall/policies/{policy_id}/enabled")
def policy_enabled(policy_id: str, body: dict = Body(...)):
    return apply_fix(client(), "enable_policy" if body.get("enabled") else "disable_policy", {"policyId": policy_id})


@app.delete("/api/firewall/policies/{policy_id}")
def delete_policy(policy_id: str):
    c = client()
    c.api("DELETE", c.sp(f"/firewall/policies/{policy_id}"))
    return {"ok": True}


@app.get("/api/dns")
def dns():
    return client().dns_policies()


@app.get("/api/vpn")
def vpn():
    c = client()
    try:
        tunnels = c.vpn_tunnels()
    except UniFiError:
        tunnels = []
    return {"servers": c.vpn_servers(), "tunnels": tunnels}


@app.get("/api/wans")
def wans():
    return client().wans()


@app.get("/api/dpi/categories")
def dpi_categories():
    return client().dpi_categories()


@app.get("/api/vouchers")
def vouchers():
    return client().vouchers()


# ------------------------------------------------------------ classic API
@app.get("/api/health")
def health():
    return client().health()


@app.get("/api/sysinfo")
def sysinfo():
    return client().sysinfo()


@app.get("/api/events")
def events(limit: int = Query(300, le=3000), hours: int = Query(72, le=24 * 30), kind: str | None = None):
    c = client()
    evs = [explain_system_event(e) for e in c.events(limit, hours)]
    if kind:
        evs = [e for e in evs if e["kind"] == kind]
    return evs


@app.get("/api/alarms")
def alarms(limit: int = Query(200, le=2000)):
    out = []
    for a in client().alarms(limit):
        e = explain_system_event(a)
        e["archived"] = a.get("archived", False)
        e["hint"] = ALARM_HINTS.get(a.get("key", ""))
        out.append(e)
    return out


@app.get("/api/threats")
def threats(limit: int = Query(500, le=5000), days: int = Query(7, le=90)):
    import time as _t
    c = client()
    now = int(_t.time() * 1000)
    evs = c.ips_events(limit, now - days * 86400 * 1000, now)
    by_ip: dict[str, dict] = {}
    try:
        for cl in c.clients():
            if cl.get("ipAddress"):
                by_ip[cl["ipAddress"]] = cl
    except UniFiError:
        pass
    explained = [explain_event(e, by_ip) for e in evs]
    return {"summary": summarize(explained), "events": explained}


@app.get("/api/security-settings")
def security_settings():
    c = client()
    keys = ["ips", "usg", "mgmt", "dpi", "guest_access", "connectivity", "country_access", "super_mgmt", "ntp", "dns"]
    out = {}
    for s in c.settings():
        if s.get("key") in keys:
            out[s["key"]] = {k: v for k, v in s.items() if not k.startswith("x_") or k == "x_ssh_enabled"}
    return out


# ---------------------------------------------------------------- audit
@app.get("/api/audit")
def audit():
    return SecurityAudit(client()).run()


@app.post("/api/audit/apply")
def audit_apply(body: dict = Body(...)):
    action = body.get("action")
    params = body.get("params") or {}
    if not action:
        raise HTTPException(400, "action obrigatoria")
    return apply_fix(client(), action, params)


# ----------------------------------------------------------- continuidade
monitor = FailoverMonitor(client)


@app.get("/api/continuity/dns-ad")
def continuity_dns_ad(adServers: str | None = None):
    """Detecta VLANs com DNS de Active Directory sequestrado pelo content filtering."""
    servers = [s.strip() for s in (adServers or "").split(",") if s.strip()]
    return build_ad_dns_plan(client(), {"adServers": servers})


@app.post("/api/continuity/dns-ad/apply")
def continuity_dns_ad_apply(body: dict = Body(None)):
    return apply_ad_dns_plan(client(), body or {})


@app.post("/api/continuity/dns-ad/step")
def continuity_dns_ad_step(body: dict = Body(...)):
    action = body.get("action")
    if not action:
        raise HTTPException(400, "action obrigatoria")
    return apply_ad_dns_step(client(), action, body.get("params") or {})


@app.get("/api/continuity/wan")
def continuity_wan():
    c = client()
    return {"snapshot": wan_snapshot(c), "vpn": plan_vpn_reconcile(c), "monitor": monitor.status()}


@app.get("/api/continuity/wan/simulate")
def continuity_wan_simulate(targetWanId: str | None = None):
    """Somente leitura: mostra o efeito de um failover antes que ele aconteca."""
    return simulate_failover(client(), targetWanId)


@app.post("/api/continuity/vpn/reconcile")
def continuity_vpn_reconcile(body: dict = Body(None)):
    dry = True if body is None else bool(body.get("dryRun", True))
    return reconcile_vpn(client(), dry_run=dry)


@app.post("/api/continuity/monitor")
def continuity_monitor(body: dict = Body(...)):
    if body.get("enabled"):
        return monitor.start(interval=body.get("intervalSec"), auto_reconcile=bool(body.get("autoReconcile")), dry_run=bool(body.get("dryRun", True)))
    return monitor.stop()


@app.post("/api/continuity/monitor/poll")
def continuity_monitor_poll():
    return {"poll": monitor.poll(), "status": monitor.status()}


# ------------------------------------------------------------ raw explorer
@app.get("/api/raw")
def raw(path: str, api: str = "integration"):
    """Explorador: chama qualquer GET da Integration API (path apos /v1) ou da API classica (path apos /s/<site>)."""
    c = client()
    if api == "classic":
        return c.classic("GET", path if path.startswith("/") else "/" + path)
    if "{siteId}" in path:
        path = path.replace("{siteId}", c.site()["id"])
    if not path.startswith("/v1"):
        path = "/v1" + (path if path.startswith("/") else "/" + path)
    return c.api("GET", path)


@app.get("/api/endpoints")
def endpoints():
    spec = ROOT / "docs" / "integration-endpoints.json"
    if spec.exists():
        return json.loads(spec.read_text())
    return []


# ---------------------------------------------------------------- static
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
