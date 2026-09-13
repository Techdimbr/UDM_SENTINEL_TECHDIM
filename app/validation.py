"""Validacao autorizada do IDS/IPS e do firewall do proprio equipamento.

O objetivo e responder a uma pergunta que nenhuma tela do UniFi responde: *o IPS que
esta ligado realmente detecta alguma coisa?* Um IPS mal configurado parece identico a
um IPS funcionando - a diferenca so aparece durante um incidente real, tarde demais.

Como isto e feito com seguranca
-------------------------------
Todos os testes aqui sao *gatilhos benignos de assinatura*: trafego que casa com uma
regra conhecida do Suricata sem carregar nenhum payload capaz de causar dano. Nao ha
exploracao real, nao ha flood e nao ha alteracao de estado em nenhum alvo.

Travas aplicadas em codigo, nao apenas documentadas:

* ``authorized=True`` explicito em toda execucao - sem isso nada roda;
* alvo de varredura obrigatoriamente em faixa privada E pertencente as redes do
  proprio site (gateway ou sub-rede declarada no controlador), o que impede apontar
  a ferramenta para um terceiro;
* varredura limitada a ``MAX_PORTS`` portas, sequencial, com timeout curto e pausa
  entre conexoes - e um teste de alcance, nao uma varredura agressiva nem um flood;
* somente ``connect()`` TCP comum: nada de pacotes forjados, SYN flood ou raw socket;
* destinos externos restritos a ``ALLOWED_EXTERNAL_HOSTS``, que sao servicos
  publicos existentes justamente para testar deteccao.

Depois da execucao o modulo relê os eventos do IPS na janela de tempo do teste e
correlaciona: isso transforma "o IPS esta ligado" em "o IPS detectou N de M testes".
"""
from __future__ import annotations

import socket
import time
from ipaddress import ip_address, ip_network
from typing import Any

import httpx

from .unifi_client import UniFiClient, UniFiError

MAX_PORTS = 16
CONNECT_TIMEOUT = 0.3
PORT_DELAY = 0.05
HTTP_TIMEOUT = 6.0

# Hosts publicos mantidos para teste de deteccao. Nada aqui e infraestrutura de
# terceiros sendo atacada: sao endpoints que existem para este fim.
ALLOWED_EXTERNAL_HOSTS = {"testmyids.com", "www.eicar.org", "secure.eicar.org"}

# Portas administrativas classicas - o que interessa saber se esta alcancavel.
DEFAULT_SCAN_PORTS = [22, 23, 53, 80, 443, 445, 3389, 8080, 8443, 8880, 1900, 5000]


class NotAuthorized(Exception):
    """Execucao sem confirmacao explicita de propriedade do equipamento."""


class UnsafeTarget(Exception):
    """Alvo fora da propria rede."""


# ----------------------------------------------------------------- catalogo
TESTS: list[dict[str, Any]] = [
    {
        "id": "attack_response",
        "name": "Resposta de ataque (saida de comando root)",
        "kind": "http",
        "category": "emerging-attackresponse / GPL ATTACK_RESPONSE",
        "sends": "GET http://testmyids.com/ - a pagina devolve a string 'uid=0(root) gid=0(root)'.",
        "why": "E o teste canonico de IDS: a resposta imita a saida do comando 'id' executado como root, "
               "que e o que um invasor veria apos comprometer um servidor. O trafego em si e um GET comum.",
        "expects": "GPL ATTACK_RESPONSE id check returned root (SID 2100498)",
        "match": ["attack_response", "id check", "returned root", "2100498"],
        "harm": "Nenhum: baixa uma pagina de texto de um site publico mantido para este proposito.",
    },
    {
        "id": "bad_user_agent",
        "name": "User-Agent de ferramenta maliciosa",
        "kind": "http",
        "category": "emerging-user_agents",
        "sends": "GET http://testmyids.com/ com cabecalho User-Agent: BlackSun.",
        "why": "Varias regras do ET identificam ferramentas pelo User-Agent. Validar esta categoria mostra se o "
               "IPS inspeciona cabecalhos HTTP e nao apenas IPs de reputacao.",
        "expects": "ET USER_AGENTS Suspicious User Agent",
        "match": ["user_agent", "user agent", "blacksun", "suspicious"],
        "harm": "Nenhum: uma unica requisicao HTTP com cabecalho diferente.",
    },
    {
        "id": "eicar",
        "name": "Arquivo de teste EICAR",
        "kind": "http",
        "category": "emerging-malware / antivirus",
        "sends": "GET https://secure.eicar.org/eicar.com.txt - string padrao de 68 bytes.",
        "why": "O EICAR e um arquivo inofensivo definido por norma da industria justamente para testar deteccao "
               "de malware sem usar um virus real. Valida a inspecao de download.",
        "expects": "Deteccao de assinatura de malware no download",
        "match": ["eicar", "malware", "trojan"],
        "harm": "Nenhum ao equipamento. Atencao: o antivirus da maquina que roda o painel provavelmente vai "
                "sinalizar e apagar o arquivo - esse e exatamente o comportamento esperado.",
        "optIn": True,
    },
    {
        "id": "dns_dynamic",
        "name": "Consulta DNS a dominio de DNS dinamico",
        "kind": "dns",
        "category": "emerging-dns / emerging-info",
        "sends": "Resolucao DNS de um dominio de DNS dinamico frequentemente usado por malware.",
        "why": "Malware resolve o dominio do C&C antes de conectar. Valida se o gateway inspeciona DNS - e, de "
               "quebra, mostra se o content filtering esta interceptando a porta 53.",
        "expects": "ET DNS Query to a *.dyndns domain / informativo",
        "match": ["dns", "dyndns", "dynamic"],
        "harm": "Nenhum: apenas uma consulta de nome, sem conexao com o resultado.",
    },
    {
        "id": "port_scan",
        "name": "Varredura curta do proprio gateway",
        "kind": "scan",
        "category": "emerging-scan",
        "sends": f"connect() TCP sequencial em ate {MAX_PORTS} portas administrativas do seu proprio gateway.",
        "why": "Valida duas coisas de uma vez: se o IPS percebe reconhecimento vindo de dentro da rede, e quais "
               "portas administrativas estao de fato alcancaveis a partir da LAN.",
        "expects": "ET SCAN / deteccao de varredura de portas",
        "match": ["scan", "nmap", "portscan", "sweep"],
        "harm": "Nenhum: conexoes TCP normais, uma de cada vez, com timeout curto. Nao ha pacote forjado nem volume.",
    },
]


# ------------------------------------------------------------------ travas
def ensure_authorized(params: dict) -> None:
    if not params.get("authorized"):
        raise NotAuthorized(
            "Confirme que o equipamento testado e seu (ou que voce tem autorizacao escrita do dono) "
            "antes de executar a validacao."
        )


def owned_targets(c: UniFiClient) -> dict[str, Any]:
    """Monta a lista do que pode ser alvo: gateways e sub-redes do proprio site."""
    gateways: list[str] = []
    subnets: list[str] = []
    try:
        for n in c.networks():
            v4 = (n.get("ipv4Configuration") or {})
            host, plen = v4.get("hostIpAddress"), v4.get("prefixLength")
            if host:
                gateways.append(host)
                if plen:
                    subnets.append(f"{host}/{plen}")
    except UniFiError:
        pass
    host = (c.cfg.host or "").replace("https://", "").replace("http://", "").split(":")[0].strip("/")
    if host:
        try:
            ip_address(host)
            if host not in gateways:
                gateways.append(host)
        except ValueError:
            pass
    return {"gateways": gateways, "subnets": subnets}


def validate_target(c: UniFiClient, target: str) -> str:
    """Garante que o alvo e um IP privado pertencente a propria infraestrutura."""
    try:
        addr = ip_address(target)
    except ValueError as e:
        raise UnsafeTarget(f"'{target}' nao e um endereco IP valido.") from e
    if not addr.is_private:
        raise UnsafeTarget(
            f"{target} e um endereco publico. Esta ferramenta so testa equipamento na sua propria rede - "
            "apontar varredura para um endereco de terceiro nao e algo que ela faca."
        )
    owned = owned_targets(c)
    if target in owned["gateways"] or addr.is_loopback:
        return target
    for net in owned["subnets"]:
        try:
            if addr in ip_network(net, strict=False):
                return target
        except ValueError:
            continue
    raise UnsafeTarget(
        f"{target} nao pertence a nenhuma rede deste site ({', '.join(owned['subnets']) or 'nenhuma detectada'}). "
        "Informe o IP do seu gateway ou de um host das suas VLANs."
    )


# ------------------------------------------------------------------ testes
def _http_test(url: str, headers: dict | None = None) -> dict:
    host = httpx.URL(url).host
    if host not in ALLOWED_EXTERNAL_HOSTS:
        raise UnsafeTarget(f"Host externo nao permitido: {host}")
    try:
        r = httpx.get(url, headers=headers or {}, timeout=HTTP_TIMEOUT, follow_redirects=True)
        return {"reached": True, "status": r.status_code, "bytes": len(r.content)}
    except httpx.HTTPError as e:
        return {"reached": False, "error": str(e)[:200]}


def _dns_test(name: str) -> dict:
    try:
        infos = socket.getaddrinfo(name, None)
        return {"reached": True, "resolved": sorted({i[4][0] for i in infos})[:5]}
    except OSError as e:
        return {"reached": False, "error": str(e)[:200]}


def _scan_test(target: str, ports: list[int]) -> dict:
    """connect() TCP sequencial, limitado. Reporta o que respondeu."""
    ports = [p for p in ports if 1 <= int(p) <= 65535][:MAX_PORTS]
    open_ports, closed, filtered = [], [], []
    for p in ports:
        s = socket.socket()
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect((target, int(p)))
            open_ports.append(p)
        except TimeoutError:
            filtered.append(p)
        except OSError:
            closed.append(p)
        finally:
            s.close()
        time.sleep(PORT_DELAY)
    return {"reached": True, "target": target, "scanned": ports, "open": open_ports, "closed": closed, "filtered": filtered}


def run_validation(c: UniFiClient, params: dict) -> dict:
    """Executa os testes selecionados e correlaciona com os eventos do IPS."""
    ensure_authorized(params)
    selected = params.get("tests") or [t["id"] for t in TESTS if not t.get("optIn")]
    target = params.get("target")
    ports = params.get("ports") or DEFAULT_SCAN_PORTS

    if "port_scan" in selected:
        if not target:
            owned = owned_targets(c)
            target = owned["gateways"][0] if owned["gateways"] else None
        if not target:
            raise UnsafeTarget("Nenhum gateway detectado; informe o IP do alvo dentro da sua rede.")
        target = validate_target(c, target)

    started = int(time.time() * 1000)
    results = []
    for t in TESTS:
        if t["id"] not in selected:
            continue
        if t["kind"] == "http":
            url = "https://secure.eicar.org/eicar.com.txt" if t["id"] == "eicar" else "http://testmyids.com/"
            out = _http_test(url, {"User-Agent": "BlackSun"} if t["id"] == "bad_user_agent" else None)
        elif t["kind"] == "dns":
            out = _dns_test("test.dyndns.org")
        else:
            out = _scan_test(target, ports)
        results.append({**{k: v for k, v in t.items() if k != "match"}, "executed": out})

    return {
        "startedAt": started,
        "finishedAt": int(time.time() * 1000),
        "target": target,
        "results": results,
        "correlated": False,
        "note": "Os eventos do IPS levam alguns segundos para aparecer. Use 'Verificar detecções' para correlacionar.",
    }


def correlate(c: UniFiClient, started_ms: int, test_ids: list[str], window_extra_ms: int = 120_000) -> dict:
    """Relê os eventos do IPS na janela do teste e diz o que foi detectado."""
    if not c.classic_available():
        return {"available": False, "reason": "A API classica nao respondeu - sem ela nao ha como ler os eventos do IPS."}
    try:
        events = c.ips_events(500, started_ms - 5000, int(time.time() * 1000) + window_extra_ms)
    except UniFiError as e:
        return {"available": False, "reason": str(e)}

    by_test = {}
    for t in TESTS:
        if t["id"] not in test_ids:
            continue
        hits = []
        for ev in events:
            blob = " ".join(str(ev.get(k) or "") for k in
                            ("inner_alert_signature", "inner_alert_category", "catname")).lower()
            sid = str(ev.get("inner_alert_signature_id") or "")
            if any(m in blob or m == sid for m in t["match"]):
                hits.append({
                    "signature": ev.get("inner_alert_signature"),
                    "action": ev.get("inner_alert_action"),
                    "blocked": (ev.get("inner_alert_action") or "").lower() in ("blocked", "drop", "dropped"),
                    "time": ev.get("time"),
                })
        by_test[t["id"]] = {"name": t["name"], "detected": bool(hits), "expects": t["expects"], "hits": hits[:5]}

    detected = sum(1 for v in by_test.values() if v["detected"])
    blocked = sum(1 for v in by_test.values() if any(h["blocked"] for h in v["hits"]))
    total = len(by_test)
    if total and detected == total:
        verdict = "O IPS detectou todos os testes executados."
    elif detected:
        verdict = f"O IPS detectou {detected} de {total} testes. Os demais passaram sem alerta - verifique se as categorias correspondentes estao ativas."
    else:
        verdict = ("Nenhum teste gerou alerta. Confira se o IPS esta em modo Prevenir, se as categorias estao ativas e se "
                   "o trafego do teste realmente atravessou o gateway (a maquina que roda o painel precisa sair pela WAN do UDM).")
    return {
        "available": True,
        "eventsInWindow": len(events),
        "byTest": by_test,
        "detected": detected,
        "blockedCount": blocked,
        "total": total,
        "verdict": verdict,
    }
