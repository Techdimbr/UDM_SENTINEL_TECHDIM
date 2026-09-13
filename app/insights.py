"""O que a rede acessou: aplicacoes, categorias e destinos externos.

Limite importante e honesto: o UniFi **nao guarda um historico de URLs visitadas**.
O que existe e a identificacao por DPI (qual aplicacao/categoria consumiu banda) e os
destinos que aparecem em eventos do IPS e em sessoes. Um relatorio de "todos os sites
que o usuario X abriu" nao e algo que o controlador tenha para entregar - qualquer
painel que prometa isso a partir da API do UniFi esta inventando.

O que da para montar com precisao:
  * ranking de aplicacoes e categorias por trafego, do site e por cliente (DPI);
  * destinos externos concretos vistos em eventos do IPS, com pais;
  * historico de sessoes de cliente (quando conectou, quanto trafegou).
"""
from __future__ import annotations

import contextlib
from typing import Any

from .threats import explain_event
from .unifi_client import UniFiClient, UniFiError


# O id de aplicacao do DPI e composto: (categoria << 16) | aplicacao.
def split_app_id(app_id: Any) -> tuple[int | None, int | None]:
    try:
        v = int(app_id)
    except (TypeError, ValueError):
        return None, None
    return v >> 16, v & 0xFFFF


def _name_maps(c: UniFiClient) -> tuple[dict, dict]:
    """Resolve nomes de categoria/aplicacao pela Integration API (quando disponivel)."""
    cats: dict[int, str] = {}
    apps: dict[int, str] = {}
    try:
        for x in c.dpi_categories():
            cid = x.get("id")
            if cid is not None:
                try:
                    cats[int(cid)] = x.get("name") or str(cid)
                except (TypeError, ValueError):
                    continue
    except UniFiError:
        pass
    try:
        for x in c.dpi_applications():
            aid = x.get("id")
            if aid is not None:
                try:
                    apps[int(aid)] = x.get("name") or str(aid)
                except (TypeError, ValueError):
                    continue
    except UniFiError:
        pass
    return cats, apps


def _label(entry: dict, cats: dict, apps: dict) -> dict:
    raw_app = entry.get("app")
    cat_id = entry.get("cat")
    app_name = None
    if raw_app is not None:
        app_name = apps.get(int(raw_app)) if str(raw_app).isdigit() else None
        if not app_name:
            hi, lo = split_app_id(raw_app)
            app_name = apps.get(lo) or apps.get(int(raw_app) if str(raw_app).isdigit() else -1)
            if cat_id is None and hi is not None:
                cat_id = hi
    cat_name = cats.get(int(cat_id)) if cat_id is not None and str(cat_id).lstrip("-").isdigit() else None
    return {
        "app": app_name or (f"app {raw_app}" if raw_app is not None else None),
        "category": cat_name or (f"categoria {cat_id}" if cat_id is not None else "nao classificado"),
        "rxBytes": entry.get("rx_bytes", 0),
        "txBytes": entry.get("tx_bytes", 0),
        "totalBytes": (entry.get("rx_bytes") or 0) + (entry.get("tx_bytes") or 0),
        "packets": (entry.get("rx_packets") or 0) + (entry.get("tx_packets") or 0),
        "clients": entry.get("clients"),
    }


def traffic_overview(c: UniFiClient, top: int = 25) -> dict:
    """Ranking de aplicacoes e categorias do site, e por cliente."""
    if not c.classic_available():
        return {"available": False, "reason": "As estatisticas de DPI vem da API classica, que nao respondeu nesta conexao."}

    cats, apps = _name_maps(c)
    out: dict[str, Any] = {"available": True, "dpiEnabled": True, "byApp": [], "byCategory": [], "byClient": []}

    try:
        rows = c.site_dpi("by_app")
        items = []
        for r in rows:
            items.extend(r.get("by_app", []) if isinstance(r, dict) and "by_app" in r else [r])
        labeled = [_label(x, cats, apps) for x in items]
        out["byApp"] = sorted(labeled, key=lambda x: -x["totalBytes"])[:top]
    except UniFiError as e:
        out["byApp"] = []
        out["appsError"] = str(e)

    try:
        rows = c.site_dpi("by_cat")
        items = []
        for r in rows:
            items.extend(r.get("by_cat", []) if isinstance(r, dict) and "by_cat" in r else [r])
        labeled = [_label(x, cats, apps) for x in items]
        agg: dict[str, dict] = {}
        for x in labeled:
            d = agg.setdefault(x["category"], {"category": x["category"], "totalBytes": 0, "rxBytes": 0, "txBytes": 0})
            d["totalBytes"] += x["totalBytes"]; d["rxBytes"] += x["rxBytes"]; d["txBytes"] += x["txBytes"]
        out["byCategory"] = sorted(agg.values(), key=lambda x: -x["totalBytes"])[:top]
    except UniFiError as e:
        out["catsError"] = str(e)

    try:
        names = {}
        with contextlib.suppress(UniFiError):
            names = {(x.get("macAddress") or "").lower(): x.get("name") for x in c.clients()}
        per_client = []
        for row in c.client_dpi("by_app"):
            mac = (row.get("mac") or "").lower()
            entries = [_label(x, cats, apps) for x in row.get("by_app", [])]
            total = sum(e["totalBytes"] for e in entries)
            per_client.append({
                "mac": mac,
                "name": names.get(mac) or row.get("hostname") or mac,
                "totalBytes": total,
                "topApps": sorted(entries, key=lambda x: -x["totalBytes"])[:5],
            })
        out["byClient"] = sorted(per_client, key=lambda x: -x["totalBytes"])[:top]
    except UniFiError as e:
        out["clientsError"] = str(e)

    if not out["byApp"] and not out["byCategory"]:
        out["dpiEnabled"] = False
        out["hint"] = ("Nenhum dado de DPI retornou. Ative Settings > Security > Traffic & Device Identification "
                       "no UniFi; sem isso o gateway nao classifica o trafego e nao ha o que listar aqui.")
    return out


def external_destinations(c: UniFiClient, days: int = 7, top: int = 40) -> dict:
    """Destinos externos concretos vistos nos eventos do IPS (com pais e risco)."""
    import time as _t
    if not c.classic_available():
        return {"available": False, "reason": "Os eventos do IPS vem da API classica, que nao respondeu nesta conexao."}
    now = int(_t.time() * 1000)
    try:
        raw = c.ips_events(1000, now - days * 86400 * 1000, now)
    except UniFiError as e:
        return {"available": False, "reason": str(e)}

    by_ip: dict[str, dict] = {}
    for ev in raw:
        e = explain_event(ev)
        for side in ("src", "dst"):
            node = e[side]
            if not node.get("ip") or node.get("internal"):
                continue
            d = by_ip.setdefault(node["ip"], {
                "ip": node["ip"], "country": node.get("country"), "count": 0,
                "risks": set(), "titles": set(), "blocked": 0, "direction": e["direction"],
            })
            d["count"] += 1
            d["risks"].add(e["risk"])
            d["titles"].add(e["title"])
            if e["blocked"]:
                d["blocked"] += 1

    order = {"critico": 4, "alto": 3, "medio": 2, "baixo": 1}
    items = []
    for d in by_ip.values():
        worst = max(d["risks"], key=lambda r: order.get(r, 0)) if d["risks"] else "baixo"
        items.append({**{k: v for k, v in d.items() if k not in ("risks", "titles")},
                      "maxRisk": worst, "types": sorted(d["titles"])})
    items.sort(key=lambda x: (-order.get(x["maxRisk"], 0), -x["count"]))
    return {"available": True, "days": days, "total": len(items), "destinations": items[:top]}


def session_history(c: UniFiClient, hours: int = 24, limit: int = 300) -> dict:
    """Historico de sessoes de clientes: quem conectou, quando e quanto trafegou."""
    if not c.classic_available():
        return {"available": False, "reason": "O historico de sessoes vem da API classica, que nao respondeu nesta conexao."}
    try:
        rows = c.sessions(limit, hours)
    except UniFiError as e:
        return {"available": False, "reason": str(e)}
    out = []
    for s in rows:
        out.append({
            "mac": s.get("mac"),
            "name": s.get("hostname") or s.get("name") or s.get("mac"),
            "ip": s.get("ip"),
            "start": s.get("assoc_time") or s.get("start"),
            "end": s.get("end"),
            "durationSec": s.get("duration"),
            "rxBytes": s.get("rx_bytes"),
            "txBytes": s.get("tx_bytes"),
            "ap": s.get("ap_mac"),
            "network": s.get("network") or s.get("essid"),
        })
    out.sort(key=lambda x: -(x["start"] or 0))
    return {"available": True, "hours": hours, "total": len(out), "sessions": out}


def anomalies(c: UniFiClient, hours: int = 24) -> dict:
    if not c.classic_available():
        return {"available": False, "reason": "Anomalias vem da API classica, que nao respondeu nesta conexao."}
    try:
        return {"available": True, "items": c.anomalies(hours)}
    except UniFiError as e:
        return {"available": False, "reason": str(e)}
