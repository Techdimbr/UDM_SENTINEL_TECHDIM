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
