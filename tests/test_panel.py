"""Testes de integracao: painel FastAPI contra o servidor mock do UDM Pro."""
from __future__ import annotations

import os
import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from tests import mock_udm


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def mock_server():
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(mock_udm.mock, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


@pytest.fixture(scope="session")
def api(mock_server, tmp_path_factory):
    os.environ["UNIFI_PANEL_CONFIG"] = str(tmp_path_factory.mktemp("cfg") / "config.json")
    os.environ["UNIFI_HOST"] = mock_server
    os.environ["UNIFI_API_KEY"] = mock_udm.API_KEY
    from app.main import app, reset_client
    reset_client()
    return TestClient(app)


# ------------------------------------------------------------- unidade
def test_classify_uses_et_class():
    from app.threats import classify
    assert classify("ET SCAN Potential SSH Scan", "Attempted Information Leak", "emerging-scan")["title"].startswith("Varredura")
    assert classify("ET MALWARE Win32/Emotet CnC Beacon", "A Network Trojan was detected")["risk"] == "critico"
    assert classify("ET DROP Dshield Block Listed Source group 1", "Misc Attack", "emerging-dshield")["title"] == "Comunicacao com IP de ma reputacao"
    assert classify("ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain")["title"].startswith("Tentativa de exploracao")
    assert classify("Something unknown", "") is not None


def test_explain_event_direction_cve_and_device():
    from app.threats import explain_event
    ev = mock_udm.IPS_EVENTS[2]
    e = explain_event(ev)
    assert e["cve"] == "CVE-2021-44228" and "nvd.nist.gov" in e["cveUrl"]
    assert e["direction"] == "entrada" and e["blocked"] is True
    e0 = explain_event(mock_udm.IPS_EVENTS[0], {"192.168.20.15": {"name": "Camera-Quintal"}})
    assert e0["direction"] == "saida" and e0["blocked"] is False
    assert e0["internalDevice"]["name"] == "Camera-Quintal"
    assert any("Camera-Quintal" in s for s in e0["steps"])


def test_build_block_policy_schema():
    from app.audit import build_block_policy
    body = build_block_policy({"name": "x", "sourceZoneId": "a", "destinationZoneId": "b", "destinationPorts": ["22", "8000-8100"], "protocol": "TCP", "connectionStates": ["NEW"]})
    items = body["destination"]["trafficFilter"]["portFilter"]["items"]
    assert items == [{"type": "PORT_NUMBER", "value": 22}, {"type": "PORT_NUMBER_RANGE", "start": 8000, "stop": 8100}]
    assert body["ipProtocolScope"]["protocolFilter"] == {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "TCP"}}
    assert body["connectionStateFilter"] == ["NEW"]


# ---------------------------------------------------------------- rotas
def test_config_is_masked(api):
    c = api.get("/api/config").json()
    assert c["configured"] and mock_udm.API_KEY not in c["api_key"] and "…" in c["api_key"]


def test_bad_key_gives_401(api, mock_server):
    r = api.post("/api/config/test", json={"mode": "local", "host": mock_server, "api_key": "wrong-key"})
    assert r.status_code == 401


def test_connection_and_overview(api):
    t = api.post("/api/config/test").json()
    assert t["applicationVersion"] == "10.4.57" and t["site"]["name"] == "Casa" and t["classicApi"] is True
    o = api.get("/api/overview").json()
    assert len(o["devices"]) == 3 and len(o["clients"]) == 3 and o["threats"]["total"] == 15
    assert o["errors"] == {} and o["health"][2]["status"] == "warning"


def test_threats_summary(api):
    d = api.get("/api/threats?days=7").json()
    s = d["summary"]
    assert s["blocked"] == 9 and s["detectedOnly"] == 6
    assert all(not ip["ip"].startswith("192.168.") for ip in s["topSources"])
    assert s["internalDevices"][0]["name"] == "Camera-Quintal"


def test_audit_findings(api):
    a = api.get("/api/audit").json()
    titles = {f["title"] for f in a["findings"]}
    assert a["grade"] in "ABCDE" and a["counts"]["critico"] >= 3
    assert any("Visitantes" in t and "aberta" in t for t in titles)
    assert any("PPTP" in t for t in titles)
    assert any("UPnP" in t for t in titles)
    assert any("External -> Internal" in t for t in titles)
    assert any("Wi-Fi 6" in t or "U6" in t for t in titles)
    assert any("Câmeras" in t or "Cameras" in t for t in titles)


def test_apply_fix_camera_and_wifi3(api, restore_mock):
    # Testar ação para bloquear WAN de rede de Câmeras
    cam_net = mock_udm.NETS["Cameras"]
    r = api.post("/api/audit/apply", json={"action": "block_network_wan", "params": {"networkId": cam_net["id"]}})
    assert r.status_code == 200
    net = api.get("/api/networks").json()
    c_net = next(n for n in net if n["id"] == cam_net["id"])
    assert c_net["internetAccessEnabled"] is False

    # Testar ação para WPA2/WPA3 Misto
    w_id = mock_udm.WIFI[1]["id"]
    r = api.post("/api/audit/apply", json={"action": "wifi_enable_wpa3", "params": {"wifiId": w_id}})
    assert r.status_code == 200


def test_apply_fix_ips_mode_and_upnp(api):
    r = api.post("/api/audit/apply", json={"action": "set_ips_mode", "params": {"mode": "ips"}})
    assert r.status_code == 200
    r = api.post("/api/audit/apply", json={"action": "set_usg_flag", "params": {"field": "upnp_enabled", "value": False}})
    assert r.status_code == 200
    sec = api.get("/api/security-settings").json()
    assert sec["ips"]["ips_mode"] == "ips" and sec["usg"]["upnp_enabled"] is False


def test_firewall_policy_lifecycle(api):
    fw = api.get("/api/firewall").json()
    zones = {z["name"]: z["id"] for z in fw["zones"]}
    body = {"name": "Teste IoT->Internal", "sourceZoneId": zones["Guest"], "destinationZoneId": zones["Internal"], "destinationPorts": ["445"], "protocol": "TCP_UDP", "loggingEnabled": False}
    prev = api.post("/api/firewall/policies", json={**body, "preview": True}).json()["preview"]
    assert prev["action"]["type"] == "BLOCK" and prev["ipProtocolScope"]["protocolFilter"]["type"] == "PRESET"
    assert api.post("/api/firewall/policies", json=body).status_code == 200
    pol = next(p for p in api.get("/api/firewall").json()["policies"] if p["name"] == body["name"])
    assert api.post(f"/api/firewall/policies/{pol['id']}/logging", json={"enabled": True}).status_code == 200
    assert api.post(f"/api/firewall/policies/{pol['id']}/enabled", json={"enabled": False}).status_code == 200
    pol = next(p for p in api.get("/api/firewall").json()["policies"] if p["id"] == pol["id"])
    assert pol["loggingEnabled"] is True and pol["enabled"] is False
    assert api.delete(f"/api/firewall/policies/{pol['id']}").status_code == 200
    assert all(p["id"] != pol["id"] for p in api.get("/api/firewall").json()["policies"])


def test_wifi_passphrase_hidden(api):
    for w in api.get("/api/wifi").json():
        sec = w.get("securityConfiguration") or {}
        if "passphrase" in sec:
            assert sec["passphrase"] == "••••••••" and sec["passphraseLength"] > 0


def test_events_alarms_and_clients(api):
    evs = api.get("/api/events").json()
    assert {e["kind"] for e in evs} >= {"seguranca", "alerta", "info"}
    assert api.get("/api/alarms").json()[0]["title"]
    cl = api.get("/api/clients").json()
    assert cl[0]["extra"]["oui"] == "Dell"
    assert api.post("/api/clients/block", json={"mac": cl[0]["macAddress"]}).status_code == 200


def test_raw_explorer_and_static(api):
    assert api.get("/api/raw?path=/v1/sites/{siteId}/devices").json()["count"] == 3
    assert api.get("/api/raw?api=classic&path=/stat/health").json()[0]["subsystem"] == "wan"
    assert len(api.get("/api/endpoints").json()) == 73
    assert "Painel UniFi" in api.get("/").text


# ------------------------------------------------- continuidade (AD / WAN)
@pytest.fixture
def restore_mock():
    """Devolve o mock ao estado inicial: os testes daqui mudam config de proposito."""
    import copy
    saved = (copy.deepcopy(mock_udm.NETS), copy.deepcopy(mock_udm.POLICIES),
             copy.deepcopy(mock_udm.NETWORKCONF), copy.deepcopy(mock_udm.WANS))
    yield
    mock_udm.NETS.clear(); mock_udm.NETS.update(saved[0])
    mock_udm.POLICIES[:] = saved[1]
    mock_udm.NETWORKCONF[:] = saved[2]
    mock_udm.WANS[:] = saved[3]


def _client(api):
    from app.main import client
    return client()


def test_detects_ad_dns_hijacked_by_content_filtering(api, restore_mock):
    """A VLAN Corp aponta para controladores de dominio E tem filtro ligado -> conflito."""
    from app.orchestrator import detect_ad_dns
    d = detect_ad_dns(_client(api))
    names = [c["name"] for c in d["conflicts"]]
    assert names == ["Corp"]
    conf = d["conflicts"][0]
    assert conf["adDnsServers"] == ["192.168.10.10", "192.168.10.11"]
    assert conf["contentFilteringValue"] == "WORK"
    assert "PREROUTING" in conf["impact"]


def test_guest_with_filter_but_no_internal_dns_is_not_flagged(api, restore_mock):
    """Guest tem content filtering ligado, mas nenhum DNS interno: filtrar ali e correto."""
    from app.orchestrator import detect_ad_dns
    d = detect_ad_dns(_client(api))
    assert "Guest" not in [c["name"] for c in d["conflicts"]]


def test_plan_leads_with_the_decisive_step(api, restore_mock):
    """A isencao do content filtering precisa vir primeiro: e a unica que vence o DNAT."""
    from app.orchestrator import build_ad_dns_plan
    plan = build_ad_dns_plan(_client(api))
    assert plan["steps"][0]["decisive"] is True
    assert plan["steps"][0]["action"] == "exempt_content_filtering"
    assert [s["decisive"] for s in plan["steps"][1:]] == [False, False]


def test_applying_plan_resolves_the_ad_dns_conflict(api, restore_mock):
    from app.orchestrator import apply_ad_dns_plan, detect_ad_dns
    c = _client(api)
    assert detect_ad_dns(c)["conflicts"]
    r = apply_ad_dns_plan(c)
    assert r["resolved"] is True and r["remaining"] == 0
    assert all(a["ok"] for a in r["applied"])
    assert not detect_ad_dns(c)["conflicts"]
    # a politica de reforco foi criada e ficou em primeiro na ordem de avaliacao
    user = [p for p in mock_udm.POLICIES if p.get("metadata", {}).get("origin") == "USER_DEFINED"]
    assert "AD DNS" in user[0]["name"]


def test_wan_snapshot_identifies_active_wan(api, restore_mock):
    from app.orchestrator import wan_snapshot
    snap = wan_snapshot(_client(api))
    assert snap["activeWanName"] == "WAN1"
    assert snap["activeWanIp"] == "203.0.113.5"
    assert len(snap["wans"]) == 2


def test_failover_strands_vpn_and_reconcile_repairs_it(api, restore_mock):
    """O problema real: WAN2 assume e a VPN continua escutando na WAN1."""
    from app.orchestrator import plan_vpn_reconcile, reconcile_vpn
    c = _client(api)
    assert plan_vpn_reconcile(c)["inSync"] is True

    mock_udm.WANS[0].update(active=False, state="STANDBY")
    mock_udm.WANS[1].update(active=True, state="UP")

    stale = plan_vpn_reconcile(c)
    assert stale["inSync"] is False
    assert stale["activeWanName"] == "WAN2"
    assert {ch["name"] for ch in stale["changes"]} == {"WireGuard Casa", "Legado"}

    dry = reconcile_vpn(c, dry_run=True)
    assert dry["dryRun"] is True and dry["applied"] == []
    assert mock_udm.NETWORKCONF[0]["wan"] == "w1", "dry-run nao pode gravar"

    done = reconcile_vpn(c, dry_run=False)
    assert all(a["ok"] for a in done["applied"])
    assert mock_udm.NETWORKCONF[0]["wan"] == "w2"
    assert plan_vpn_reconcile(c)["inSync"] is True


def test_simulate_failover_changes_nothing(api, restore_mock):
    from app.orchestrator import simulate_failover
    c = _client(api)
    before = [dict(n) for n in mock_udm.NETWORKCONF]
    sim = simulate_failover(c, "w2")
    assert sim["possible"] is True and sim["target"]["name"] == "WAN2"
    assert {i["name"] for i in sim["impacted"]} == {"WireGuard Casa", "Legado"}
    assert [dict(n) for n in mock_udm.NETWORKCONF] == before


def test_monitor_records_wan_transition(api, restore_mock):
    from app.orchestrator import FailoverMonitor
    c = _client(api)
    m = FailoverMonitor(lambda: c, interval=5)
    m.poll()
    mock_udm.WANS[0].update(active=False, state="STANDBY")
    mock_udm.WANS[1].update(active=True, state="UP")
    out = m.poll()
    assert out["transition"]["from"] == "WAN1" and out["transition"]["to"] == "WAN2"
    assert m.status()["history"][0]["toIp"] == "198.51.100.7"


def test_continuity_endpoints(api, restore_mock):
    dns = api.get("/api/continuity/dns-ad").json()
    assert dns["detection"]["conflicts"][0]["name"] == "Corp"
    assert dns["steps"][0]["decisive"] is True

    wan = api.get("/api/continuity/wan").json()
    assert wan["snapshot"]["activeWanName"] == "WAN1"
    assert wan["monitor"]["enabled"] is False

    sim = api.get("/api/continuity/wan/simulate?targetWanId=w2").json()
    assert sim["possible"] is True

    assert api.post("/api/continuity/vpn/reconcile", json={"dryRun": True}).json()["dryRun"] is True

    st = api.post("/api/continuity/monitor", json={"enabled": True, "intervalSec": 5, "dryRun": True}).json()
    assert st["enabled"] is True
    assert api.post("/api/continuity/monitor/poll").json()["status"]["last"]["activeWanName"] == "WAN1"
    assert api.post("/api/continuity/monitor", json={"enabled": False}).json()["enabled"] is False

    applied = api.post("/api/continuity/dns-ad/apply", json={}).json()
    assert applied["resolved"] is True


# ------------------------------------------------ navegacao e DPI
def test_traffic_resolves_dpi_names(api):
    t = api.get("/api/traffic").json()
    assert t["available"] is True and t["dpiEnabled"] is True
    # o id composto (categoria << 16 | app) precisa virar nome legivel
    assert t["byApp"][0]["app"] == "YouTube"
    assert t["byApp"][0]["category"] == "Streaming Media"
    assert t["byCategory"][0]["category"] == "Streaming Media"
    assert t["byClient"][0]["name"] == "PC-Joao"


def test_external_destinations_rank_by_risk(api):
    d = api.get("/api/destinations").json()
    assert d["available"] is True
    assert d["destinations"][0]["maxRisk"] == "critico"
    assert all(not x["ip"].startswith("192.168.") for x in d["destinations"])


def test_sessions_and_anomalies(api):
    s = api.get("/api/sessions").json()
    assert s["available"] is True and s["sessions"][0]["name"] == "iphone"
    assert api.get("/api/anomalies").json()["items"][0]["anomaly"] == "dns_flood"


def test_threat_detail_is_enriched(api):
    t = api.get("/api/threats").json()
    ev = next(e for e in t["events"] if e["title"].startswith("Malware"))
    assert "beacon" in ev["how"]
    assert ev["canCause"] and ev["stage"] and ev["urgency"]
    assert [m["id"] for m in ev["mitre"]] == ["T1071", "T1571", "T1105"]
    assert ev["etGroupInfo"]


# ------------------------------------------- validacao autorizada IDS/IPS
def test_validation_refuses_without_authorization(api):
    r = api.post("/api/validation/run", json={"tests": ["port_scan"]})
    assert r.status_code == 403
    assert "autoriza" in r.json()["detail"].lower()


def test_validation_refuses_public_target(api):
    r = api.post("/api/validation/run", json={"authorized": True, "tests": ["port_scan"], "target": "8.8.8.8"})
    assert r.status_code == 400
    assert "publico" in r.json()["detail"].lower()


def test_validation_refuses_private_ip_outside_this_site(api):
    r = api.post("/api/validation/run", json={"authorized": True, "tests": ["port_scan"], "target": "10.99.99.1"})
    assert r.status_code == 400
    assert "nao pertence" in r.json()["detail"].lower()


def test_validation_scan_runs_against_own_gateway(api):
    from app.validation import MAX_PORTS
    r = api.post("/api/validation/run", json={"authorized": True, "tests": ["port_scan"],
                                              "target": "192.168.1.1", "ports": list(range(9000, 9040))})
    assert r.status_code == 200
    out = r.json()["results"][0]["executed"]
    # a trava de quantidade precisa cortar a lista, independente do que foi pedido
    assert len(out["scanned"]) == MAX_PORTS


def test_validation_catalog_lists_owned_targets(api):
    v = api.get("/api/validation/tests").json()
    assert {t["id"] for t in v["tests"]} >= {"attack_response", "port_scan", "eicar"}
    assert all("match" not in t for t in v["tests"])
    assert "192.168.1.1" in v["targets"]["gateways"]


def test_validation_correlates_ips_events(api):
    import time
    started = int(time.time() * 1000) - 60_000
    r = api.post("/api/validation/correlate", json={"startedAt": started, "tests": ["port_scan", "attack_response"]}).json()
    assert r["available"] is True
    # o mock tem um ET SCAN, entao a varredura casa e a resposta de ataque nao
    assert r["byTest"]["port_scan"]["detected"] is True
    assert r["byTest"]["attack_response"]["detected"] is False
    assert r["detected"] == 1 and r["total"] == 2
