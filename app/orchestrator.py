"""Orquestracao de continuidade de rede: DNS do Active Directory e failover de WAN/VPN.

Dois problemas operacionais reais do UDM Pro sao tratados aqui.

1. DNS do Active Directory quebrado pelo content filtering
   Quando o content filtering (DNS Shield / filtragem de conteudo) e ativado numa rede,
   o gateway passa a redirecionar as consultas da porta 53 para o resolvedor externo
   ainda em PREROUTING. Como o redirecionamento acontece ANTES da etapa de filtragem,
   nenhuma regra de firewall "permitir" consegue desfaze-lo: a consulta nunca chega ao
   controlador de dominio. O efeito pratico e o AD parar de resolver (_ldap._tcp,
   _kerberos._tcp, SRV de logon), porque o resolvedor publico simplesmente nao tem
   esses registros. A unica correcao efetiva e isentar a rede do content filtering;
   a politica de firewall e a reordenacao entram como reforco, para garantir que
   nenhuma regra posterior bloqueie o trafego ate o controlador de dominio.

2. VPN presa na WAN primaria depois do failover
   O servidor VPN amarra a escuta a uma WAN especifica. Quando a WAN2 assume, o
   endpoint anunciado continua apontando para a WAN1 e os clientes nao reconectam.
   A Integration API expoe /wans e /vpn/servers apenas para LEITURA, entao a
   detecao e feita por ela e a reescrita do vinculo so e possivel pela API classica
   (/rest/networkconf). Por isso toda reescrita aqui e dry-run por padrao.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable
from typing import Any

from .unifi_client import UniFiClient, UniFiError

# Nomes de campo variam entre versoes do controlador; sondamos candidatos em vez de
# fixar um unico nome, e reportamos qual foi encontrado.
CONTENT_FILTER_FIELDS = ("contentFilteringLevel", "contentFiltering", "dnsShieldEnabled", "dnsShield", "contentFilteringEnabled")
DNS_SERVER_FIELDS = ("dnsServers", "dnsServer", "nameServers")
WAN_ACTIVE_FIELDS = ("active", "isActive", "primary", "isPrimary")
WAN_STATE_FIELDS = ("state", "status", "linkState", "connectionState")
VPN_WAN_FIELDS = ("wanId", "boundWanId", "wanInterface", "wan", "interface", "x_wan")

DNS_PORTS = [53, 853]


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _walk(obj: Any, fields: tuple[str, ...], _depth: int = 0) -> tuple[str | None, Any]:
    """Procura o primeiro campo presente em `fields`, descendo em dicionarios aninhados."""
    if not isinstance(obj, dict) or _depth > 3:
        return None, None
    for f in fields:
        if f in obj and obj[f] not in (None, ""):
            return f, obj[f]
    for v in obj.values():
        if isinstance(v, dict):
            name, found = _walk(v, fields, _depth + 1)
            if name:
                return name, found
    return None, None


# --------------------------------------------------------------- DNS do AD
def content_filter_state(net: dict) -> tuple[bool, str | None, Any]:
    """Diz se o content filtering esta ativo na rede, e por qual campo foi detectado."""
    field, value = _walk(net, CONTENT_FILTER_FIELDS)
    if field is None:
        return False, None, None
    if isinstance(value, bool):
        return value, field, value
    if isinstance(value, str):
        return value.upper() not in ("NONE", "OFF", "DISABLED"), field, value
    if isinstance(value, dict):
        return bool(value.get("enabled")), field, value
    return bool(value), field, value


def network_dns_servers(net: dict) -> list[str]:
    _, value = _walk(net, DNS_SERVER_FIELDS)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x) for x in value if x]
    return []


def detect_ad_dns(c: UniFiClient, ad_servers: list[str] | None = None) -> dict:
    """Encontra VLANs cujo DNS interno (controlador de dominio) e sequestrado pelo filtro.

    Um servidor de DNS e tratado como controlador de dominio quando e um IP privado que
    NAO e o proprio gateway da rede - ou seja, a rede aponta para um resolvedor interno
    proprio, que e exatamente o caso de um ambiente com Active Directory.
    """
    nets: list[dict] = []
    for n in c.networks():
        try:
            nets.append(c.network(n["id"]))
        except UniFiError:
            nets.append(n)

    declared = [s.strip() for s in (ad_servers or []) if s.strip()]
    conflicts, healthy, discovered = [], [], []

    for n in nets:
        if not n.get("enabled", True) or n.get("management") not in ("GATEWAY", None):
            continue
        gw_ip = (n.get("ipv4Configuration") or {}).get("hostIpAddress")
        servers = network_dns_servers(n)
        internal = [s for s in servers if _is_private(s) and s != gw_ip]
        if declared:
            internal = [s for s in internal if s in declared] or [s for s in declared if s in servers]
        discovered.extend(x for x in internal if x not in discovered)
        active, field, raw = content_filter_state(n)
        entry = {
            "networkId": n.get("id"),
            "name": n.get("name"),
            "vlanId": n.get("vlanId"),
            "zoneId": n.get("zoneId"),
            "gatewayIp": gw_ip,
            "dnsServers": servers,
            "adDnsServers": internal,
            "contentFilteringActive": active,
            "contentFilteringField": field,
            "contentFilteringValue": raw,
        }
        if internal and active:
            entry["impact"] = (
                f"As consultas DNS da VLAN {n.get('vlanId')} para {', '.join(internal)} sao redirecionadas em PREROUTING "
                "para o resolvedor do filtro de conteudo. Os registros SRV do Active Directory (_ldap._tcp, _kerberos._tcp) "
                "nao existem nesse resolvedor, entao logon, ingresso no dominio e replicacao falham."
            )
            conflicts.append(entry)
        elif internal:
            healthy.append(entry)

    return {
        "conflicts": conflicts,
        "healthy": healthy,
        "adDnsServers": discovered,
        "networksChecked": len(nets),
        "detectable": any(e.get("contentFilteringField") for e in conflicts + healthy),
    }


def _ip_filter(ips: list[str]) -> dict:
    return {"type": "IP_ADDRESS", "ipAddressFilter": {"matchOpposite": False, "ipAddresses": list(ips)}}


def build_ad_dns_plan(c: UniFiClient, params: dict | None = None) -> dict:
    """Monta o plano ordenado de correcao. Nao escreve nada."""
    params = params or {}
    det = detect_ad_dns(c, params.get("adServers"))
    steps: list[dict] = []

    for conf in det["conflicts"]:
        steps.append({
            "action": "exempt_content_filtering",
            "params": {"networkId": conf["networkId"]},
            "title": f"Isentar a rede '{conf['name']}' (VLAN {conf['vlanId']}) do content filtering",
            "why": "Este e o unico passo que realmente desfaz o sequestro: o redirecionamento acontece em PREROUTING, "
                   "antes da filtragem, entao nenhuma regra de firewall consegue reverte-lo.",
            "api": f"PUT /v1/sites/{{siteId}}/networks/{conf['networkId']}",
            "decisive": True,
        })

    ad_ips = sorted({ip for conf in det["conflicts"] for ip in conf["adDnsServers"]})
    zone_ids = sorted({conf["zoneId"] for conf in det["conflicts"] if conf.get("zoneId")})
    if ad_ips and zone_ids:
        steps.append({
            "action": "create_ad_dns_policy",
            "params": {"zoneIds": zone_ids, "adServers": ad_ips, "name": params.get("policyName") or "AD DNS - bypass do filtro de conteudo"},
            "title": f"Criar politica ALLOW para {', '.join(ad_ips)} nas portas {', '.join(map(str, DNS_PORTS))}",
            "why": "Garante que nenhuma politica posterior (bloqueio entre zonas, por exemplo) derrube a consulta "
                   "ate o controlador de dominio. Reforco, nao a correcao principal.",
            "api": "POST /v1/sites/{siteId}/firewall/policies",
            "decisive": False,
        })
        steps.append({
            "action": "prioritize_ad_dns_policy",
            "params": {},
            "title": "Mover essa politica para o topo da ordem de avaliacao",
            "why": "A primeira politica que casar decide. No topo, a liberacao do DNS do AD e avaliada antes de qualquer bloqueio.",
            "api": "PUT /v1/sites/{siteId}/firewall/policies/ordering",
            "decisive": False,
        })

    return {
        "detection": det,
        "steps": steps,
        "resolved": not det["conflicts"],
        "summary": (
            f"{len(det['conflicts'])} VLAN(s) com DNS do Active Directory sequestrado pelo content filtering."
            if det["conflicts"] else "Nenhuma VLAN com DNS de Active Directory sequestrado."
        ),
    }


def _strip(body: dict) -> dict:
    return {k: v for k, v in body.items() if k not in ("id", "metadata", "index", "default")}


def apply_ad_dns_step(c: UniFiClient, action: str, params: dict) -> dict:
    """Executa um passo do plano de DNS do AD."""
    if action == "exempt_content_filtering":
        net = c.network(params["networkId"])
        _, field, _ = content_filter_state(net)
        body = _strip(net)
        if field:
            target = body
            # o campo pode estar aninhado; localiza o dicionario que realmente o contem
            if field not in body:
                for v in body.values():
                    if isinstance(v, dict) and field in v:
                        target = v
                        break
            current = target.get(field)
            target[field] = "NONE" if isinstance(current, str) else False
        else:
            body["contentFilteringLevel"] = "NONE"
        r = c.update_network(net["id"], body)
        return {"ok": True, "message": f"Content filtering desativado em '{net.get('name')}'. O DNS da VLAN volta a ir direto ao controlador de dominio.", "result": r}

    if action == "create_ad_dns_policy":
        zone_ids = params["zoneIds"]
        body = {
            "name": params.get("name") or "AD DNS - bypass do filtro de conteudo",
            "description": "Criado pelo Painel UniFi: libera consultas ao controlador de dominio antes de qualquer bloqueio.",
            "enabled": True,
            "loggingEnabled": True,
            "action": {"type": "ALLOW"},
            "source": {"zoneId": zone_ids[0]},
            "destination": {"zoneId": params.get("destinationZoneId") or zone_ids[0], "trafficFilter": _ip_filter(params["adServers"])},
            "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6", "protocolFilter": {"type": "PRESET", "preset": {"name": "TCP_UDP"}}},
        }
        if params.get("preview"):
            return {"ok": True, "preview": body}
        r = c.create_firewall_policy(body)
        return {"ok": True, "message": f"Politica '{body['name']}' criada.", "result": r, "policyId": (r or {}).get("id")}

    if action == "prioritize_ad_dns_policy":
        pols = c.firewall_policies()
        user = [p for p in pols if (p.get("metadata") or {}).get("origin") == "USER_DEFINED"]
        target_id = params.get("policyId") or next((p["id"] for p in user if "AD DNS" in (p.get("name") or "")), None)
        if not target_id:
            raise UniFiError("Politica de DNS do AD nao encontrada para priorizar.")
        ordered = [target_id] + [p["id"] for p in user if p["id"] != target_id]
        r = c.set_firewall_ordering(ordered)
        return {"ok": True, "message": "Politica do DNS do AD movida para o topo da ordem de avaliacao.", "result": r, "order": ordered}

    raise UniFiError(f"Passo desconhecido: {action}")


def apply_ad_dns_plan(c: UniFiClient, params: dict | None = None) -> dict:
    """Executa o plano inteiro, na ordem, parando no primeiro erro."""
    plan = build_ad_dns_plan(c, params)
    results, policy_id = [], None
    for step in plan["steps"]:
        p = dict(step["params"])
        if step["action"] == "prioritize_ad_dns_policy" and policy_id:
            p["policyId"] = policy_id
        try:
            r = apply_ad_dns_step(c, step["action"], p)
            policy_id = r.get("policyId") or policy_id
            results.append({"step": step["title"], "action": step["action"], "ok": True, "message": r.get("message")})
        except UniFiError as e:
            results.append({"step": step["title"], "action": step["action"], "ok": False, "message": str(e)})
            break
    after = detect_ad_dns(c, (params or {}).get("adServers"))
    return {
        "applied": results,
        "remaining": len(after["conflicts"]),
        "resolved": not after["conflicts"],
        "verification": after,
        "message": "DNS do Active Directory liberado do filtro de conteudo." if not after["conflicts"] else f"Ainda restam {len(after['conflicts'])} VLAN(s) em conflito.",
    }


# ------------------------------------------------------ failover WAN / VPN
def wan_snapshot(c: UniFiClient) -> dict:
    """Fotografa o estado das WANs e qual esta ativa no momento."""
    wans = c.wans()
    entries = []
    for w in wans:
        _, active = _walk(w, WAN_ACTIVE_FIELDS)
        state_field, state = _walk(w, WAN_STATE_FIELDS)
        up = bool(active) or (isinstance(state, str) and state.upper() in ("UP", "ACTIVE", "CONNECTED", "OK"))
        entries.append({
            "id": w.get("id"),
            "name": w.get("name"),
            "enabled": w.get("enabled", True),
            "active": bool(active) if active is not None else None,
            "state": state,
            "stateField": state_field,
            "up": up,
            "ipAddress": (w.get("ipv4") or {}).get("ipAddress") or w.get("ipAddress"),
            "priority": w.get("failoverPriority") or w.get("priority"),
        })

    active_id = next((e["id"] for e in entries if e["active"]), None)
    if active_id is None:
        up = [e for e in entries if e["up"] and e["enabled"]]
        active_id = up[0]["id"] if up else None

    health_ip = None
    if c.classic_available():
        try:
            for h in c.health():
                if h.get("subsystem") == "wan":
                    health_ip = h.get("wan_ip") or h.get("wanIp")
        except UniFiError:
            pass

    active = next((e for e in entries if e["id"] == active_id), None)
    return {
        "at": int(time.time() * 1000),
        "wans": entries,
        "activeWanId": active_id,
        "activeWanName": active["name"] if active else None,
        "activeWanIp": (active or {}).get("ipAddress") or health_ip,
    }


def vpn_bindings(c: UniFiClient) -> dict:
    """Cruza os servidores VPN (leitura) com a configuracao gravavel da API classica."""
    servers = c.vpn_servers()
    writable: list[dict] = []
    classic_error = None
    if c.classic_available():
        try:
            writable = [n for n in c.networkconf() if "vpn" in str(n.get("purpose", "")).lower()]
        except UniFiError as e:
            classic_error = str(e)

    by_name = {str(n.get("name", "")).lower(): n for n in writable}
    out = []
    for s in servers:
        conf = by_name.get(str(s.get("name", "")).lower())
        field, bound = _walk(s, VPN_WAN_FIELDS)
        if bound is None and conf:
            field, bound = _walk(conf, VPN_WAN_FIELDS)
        out.append({
            "id": s.get("id"),
            "name": s.get("name"),
            "type": s.get("type"),
            "enabled": s.get("enabled", True),
            "boundWan": bound,
            "boundWanField": field,
            "configId": (conf or {}).get("_id") or (conf or {}).get("id"),
            "writable": bool(conf),
        })
    return {"servers": out, "writableConfigs": len(writable), "classicError": classic_error}


def plan_vpn_reconcile(c: UniFiClient) -> dict:
    """Calcula que servidores VPN estao amarrados a uma WAN que nao e mais a ativa."""
    snap = wan_snapshot(c)
    binding = vpn_bindings(c)
    active_id, active_name = snap["activeWanId"], snap["activeWanName"]
    changes = []
    for s in binding["servers"]:
        if not s["enabled"] or s["boundWan"] is None:
            continue
        bound = str(s["boundWan"])
        if bound in (str(active_id), str(active_name)):
            continue
        changes.append({
            "vpnId": s["id"],
            "name": s["name"],
            "type": s["type"],
            "from": s["boundWan"],
            "to": active_id,
            "toName": active_name,
            "field": s["boundWanField"],
            "configId": s["configId"],
            "writable": s["writable"],
            "reason": f"A VPN '{s['name']}' escuta em {s['boundWan']}, mas a WAN ativa agora e {active_name}. Clientes nao reconectam ate o vinculo mudar.",
        })
    return {
        "activeWanId": active_id,
        "activeWanName": active_name,
        "activeWanIp": snap["activeWanIp"],
        "changes": changes,
        "inSync": not changes,
        "writable": all(ch["writable"] for ch in changes) if changes else True,
        "note": None if all(ch["writable"] for ch in changes) else
                "A Integration API expoe /vpn/servers somente para leitura. A reescrita depende da API classica "
                "(/rest/networkconf), que nao respondeu nesta conexao.",
    }


def reconcile_vpn(c: UniFiClient, dry_run: bool = True) -> dict:
    """Reamarra os servidores VPN a WAN ativa. dry_run=True apenas calcula."""
    plan = plan_vpn_reconcile(c)
    if dry_run or not plan["changes"]:
        return {**plan, "dryRun": True, "applied": []}

    applied = []
    for ch in plan["changes"]:
        if not ch["writable"] or not ch["configId"]:
            applied.append({"name": ch["name"], "ok": False, "message": "Sem objeto gravavel correspondente na API classica."})
            continue
        try:
            conf = next((n for n in c.networkconf() if (n.get("_id") or n.get("id")) == ch["configId"]), None)
            if conf is None:
                applied.append({"name": ch["name"], "ok": False, "message": "Configuracao nao encontrada."})
                continue
            body = {k: v for k, v in conf.items() if not k.startswith("_") or k == "_id"}
            body[ch["field"] or "wan"] = ch["to"]
            c.update_networkconf(ch["configId"], body)
            applied.append({"name": ch["name"], "ok": True, "message": f"Vinculo movido para {ch['toName']}."})
        except UniFiError as e:
            applied.append({"name": ch["name"], "ok": False, "message": str(e)})

    after = plan_vpn_reconcile(c)
    return {**after, "dryRun": False, "applied": applied}


def simulate_failover(c: UniFiClient, target_wan_id: str | None = None) -> dict:
    """Responde 'o que aconteceria se a WAN X assumisse agora?' sem alterar nada.

    Somente leitura, entao roda com seguranca contra o equipamento em producao: e a
    forma de conferir o plano de failover sem esperar a WAN primaria cair de verdade.
    """
    snap = wan_snapshot(c)
    binding = vpn_bindings(c)
    candidates = [w for w in snap["wans"] if w["enabled"] and w["id"] != snap["activeWanId"]]
    target = next((w for w in snap["wans"] if w["id"] == target_wan_id), None) or (candidates[0] if candidates else None)
    if target is None:
        return {"possible": False, "reason": "Nao ha uma segunda WAN habilitada para assumir.", "current": snap}

    impacted = []
    for s in binding["servers"]:
        if not s["enabled"] or s["boundWan"] is None:
            continue
        bound = str(s["boundWan"])
        if bound in (str(target["id"]), str(target["name"])):
            continue
        impacted.append({
            "name": s["name"], "type": s["type"], "from": s["boundWan"], "to": target["id"], "toName": target["name"],
            "writable": s["writable"],
            "effect": f"'{s['name']}' continuaria escutando em {s['boundWan']} e os clientes ficariam sem reconectar ate o vinculo apontar para {target['name']}.",
        })

    return {
        "possible": True,
        "current": snap,
        "target": {"id": target["id"], "name": target["name"], "ipAddress": target["ipAddress"]},
        "impacted": impacted,
        "wouldSelfHeal": not impacted,
        "summary": (
            f"Se {target['name']} assumisse, {len(impacted)} servidor(es) VPN ficariam presos na WAN antiga."
            if impacted else f"Se {target['name']} assumisse, nenhum servidor VPN ficaria preso na WAN antiga."
        ),
    }


class FailoverMonitor:
    """Vigia a WAN ativa e, opcionalmente, reamarra a VPN quando ela muda.

    Roda em thread propria porque a deteccao precisa continuar mesmo com o navegador
    fechado - o failover nao espera alguem estar olhando o painel.
    """

    def __init__(self, get_client: Callable[[], UniFiClient], interval: float = 30.0):
        self._get_client = get_client
        self.interval = interval
        self.enabled = False
        self.auto_reconcile = False
        self.dry_run = True
        self.last: dict | None = None
        self.history: list[dict] = []
        self.error: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def poll(self) -> dict:
        """Uma leitura. Registra a transicao se a WAN ativa mudou."""
        try:
            snap = wan_snapshot(self._get_client())
            self.error = None
        except UniFiError as e:
            self.error = str(e)
            return {"error": str(e)}

        with self._lock:
            prev = self.last
            transition = None
            if prev and prev.get("activeWanId") != snap["activeWanId"]:
                transition = {
                    "at": snap["at"],
                    "from": prev.get("activeWanName") or prev.get("activeWanId"),
                    "to": snap.get("activeWanName") or snap.get("activeWanId"),
                    "fromIp": prev.get("activeWanIp"),
                    "toIp": snap.get("activeWanIp"),
                }
                self.history.insert(0, transition)
                del self.history[50:]
            self.last = snap

        if transition and self.auto_reconcile:
            try:
                result = reconcile_vpn(self._get_client(), dry_run=self.dry_run)
                transition["reconcile"] = {"dryRun": result["dryRun"], "changes": len(result["changes"]), "applied": result.get("applied", [])}
            except UniFiError as e:
                transition["reconcile"] = {"error": str(e)}

        return {"snapshot": snap, "transition": transition}

    def _loop(self):
        while not self._stop.wait(self.interval):
            if self.enabled:
                self.poll()

    def start(self, interval: float | None = None, auto_reconcile: bool = False, dry_run: bool = True):
        if interval:
            self.interval = max(5.0, float(interval))
        self.auto_reconcile = auto_reconcile
        self.dry_run = dry_run
        self.enabled = True
        self.poll()
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="wan-failover-monitor")
            self._thread.start()
        return self.status()

    def stop(self):
        self.enabled = False
        self._stop.set()
        return self.status()

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "autoReconcile": self.auto_reconcile,
                "dryRun": self.dry_run,
                "intervalSec": self.interval,
                "last": self.last,
                "history": list(self.history),
                "error": self.error,
                "running": bool(self._thread and self._thread.is_alive()),
            }
