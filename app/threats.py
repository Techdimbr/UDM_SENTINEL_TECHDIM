"""Base de conhecimento para interpretar ameacas detectadas pelo IDS/IPS do UniFi.

O UniFi usa o motor Suricata com regras Emerging Threats (ET). Cada evento traz
campos como `inner_alert_signature`, `inner_alert_category`, `inner_alert_severity`,
`inner_alert_action` (allowed/blocked), `src_ip`, `dest_ip`, `proto`, `srcipCountry`,
`catname` (categoria UniFi), `app_proto` etc.

Aqui traduzimos isso para uma explicacao detalhada em portugues, com nivel de
risco, o que significa, o que provavelmente aconteceu e o que fazer.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

# ---------------------------------------------------------------- categorias
# Chave: trecho (minusculo) presente em alert_category / catname / signature.
CATEGORIES: list[dict[str, Any]] = [
    {
        "match": ["trojan", "malware", "botcc", "bot command", "cnc", "c&c", "command and control"],
        "title": "Malware / Trojan / Botnet (C&C)",
        "risk": "critico",
        "what": "Trafego com assinatura de malware conhecido, trojan ou comunicacao com servidor de comando e controle (C&C) de botnet.",
        "means": "Um dispositivo da sua rede pode estar infectado e tentando 'ligar para casa' (receber comandos, exfiltrar dados ou participar de ataques). Se a origem for externa, alguem tentou entregar malware para um dispositivo interno.",
        "actions": [
            "Identifique o dispositivo interno envolvido (IP/MAC) e isole-o da rede (bloqueio de cliente).",
            "Rode antivirus/antimalware completo no dispositivo e verifique programas iniciados automaticamente.",
            "Troque senhas usadas nesse dispositivo apos a limpeza.",
            "Mantenha o IPS em modo 'Prevenir' (bloqueio) e a categoria Malware/Botnet ativa.",
        ],
    },
    {
        "match": ["exploit", "shellcode", "attack_response", "attack response", "web_specific_apps", "web_server", "web server", "sql injection", "sqli", "rce", "remote code"],
        "title": "Tentativa de exploracao de vulnerabilidade",
        "risk": "alto",
        "what": "Pacote que corresponde a um exploit conhecido (falha em servidor web, sistema operacional, roteador, camera IP etc.).",
        "means": "Alguem (geralmente scanners automatizados da internet) tentou explorar uma vulnerabilidade em um servico exposto. Se voce tem portas abertas (port forwarding) ou UPnP ativo, o alvo pode ser um servico real.",
        "actions": [
            "Verifique se o IP de destino interno realmente expoe o servico atacado (port forwarding, UPnP, DMZ).",
            "Atualize firmware/software do dispositivo alvo.",
            "Se o servico nao precisa ser acessado da internet, remova o encaminhamento de porta e desative UPnP.",
            "Restrinja acesso por regiao (GeoIP) ou por VPN em vez de expor a porta.",
        ],
    },
    {
        "match": ["scan", "recon", "reconnaissance", "nmap", "masscan", "probe"],
        "title": "Varredura / Reconhecimento de rede",
        "risk": "medio",
        "what": "Varredura de portas ou de servicos: alguem esta mapeando quais portas e servicos estao abertos.",
        "means": "E o passo inicial de quase todo ataque. Vindo da internet, e ruido constante (bots). Vindo de um IP interno, pode indicar dispositivo comprometido ou ferramenta de rede (ex.: app de scanner) em uso.",
        "actions": [
            "Se a origem for interna, investigue o dispositivo (pode ser malware ou um app de diagnostico).",
            "Confirme que nao ha servicos desnecessarios expostos na WAN.",
            "Considere bloquear paises de onde voce nunca espera acesso (Restricao por regiao).",
        ],
    },
    {
        "match": ["dos", "ddos", "denial of service", "flood"],
        "title": "Negacao de servico (DoS/DDoS)",
        "risk": "alto",
        "what": "Volume anormal de trafego ou padrao que visa derrubar um servico ou esgotar recursos.",
        "means": "Seu IP publico pode estar sendo alvo de ataque de negacao de servico, ou um dispositivo interno esta participando de um ataque (botnet).",
        "actions": [
            "Se a origem for interna, isole o dispositivo imediatamente.",
            "Ative a protecao contra DoS/SYN flood nas configuracoes de seguranca do gateway.",
            "Em ataques persistentes, contate seu provedor de internet.",
        ],
    },
    {
        "match": ["policy", "p2p", "torrent", "bittorrent", "tor", "proxy", "vpn", "anonymizer", "games"],
        "title": "Violacao de politica / Uso de P2P, TOR ou proxies",
        "risk": "baixo",
        "what": "Trafego permitido tecnicamente, mas que viola politicas comuns: torrent, rede TOR, proxies anonimos, jogos etc.",
        "means": "Nao e necessariamente um ataque. Indica um dispositivo usando aplicativos que podem expor a rede (P2P baixa arquivos de fontes nao confiaveis; TOR pode ocultar trafego malicioso).",
        "actions": [
            "Identifique o dispositivo e o usuario; avalie se o uso e legitimo.",
            "Use Restricao de trafego/DPI para bloquear categorias indesejadas se for politica da rede.",
        ],
    },
    {
        "match": ["phish", "phishing", "credential", "social engineering"],
        "title": "Phishing / Roubo de credenciais",
        "risk": "alto",
        "what": "Acesso a dominio ou padrao de trafego associado a paginas falsas de login ou roubo de credenciais.",
        "means": "Um usuario da rede provavelmente clicou em um link de e-mail/mensagem fraudulenta.",
        "actions": [
            "Avise o usuario do dispositivo para nao inserir senhas na pagina acessada.",
            "Se credenciais foram digitadas, troque-as imediatamente e ative 2FA.",
            "Ative a filtragem de DNS (Ad/Content filtering) nas redes.",
        ],
    },
    {
        "match": ["coinminer", "coin miner", "cryptomin", "mining", "crypto"],
        "title": "Mineracao de criptomoedas",
        "risk": "alto",
        "what": "Comunicacao com pool de mineracao de criptomoedas.",
        "means": "Um dispositivo esta minerando criptomoedas - quase sempre sem o conhecimento do dono (cryptojacking via malware ou script em site).",
        "actions": [
            "Identifique o dispositivo; feche navegadores e verifique processos com alto uso de CPU.",
            "Faca varredura antimalware e remova extensoes de navegador suspeitas.",
        ],
    },
    {
        "match": ["dns", "dns query", "hunting", "info"],
        "title": "Consulta DNS suspeita / Informativo",
        "risk": "baixo",
        "what": "Consulta DNS para dominio malicioso conhecido, DNS dinamico usado por malware ou informacao de auditoria.",
        "means": "Pode ser um dispositivo infectado tentando resolver o dominio do C&C, ou apenas um acesso a servico de DNS dinamico legitimo.",
        "actions": [
            "Verifique o dominio consultado. Se for desconhecido, investigue o dispositivo.",
            "Considere usar DNS com filtragem (ex.: Cloudflare Family, Quad9) via DNS Shield/filtragem.",
        ],
    },
    {
        "match": ["user_agents", "user agent", "adware", "pup", "spyware", "tracking"],
        "title": "Adware / Spyware / Software indesejado",
        "risk": "medio",
        "what": "Trafego de software indesejado (adware, spyware, rastreadores agressivos).",
        "means": "Um dispositivo tem um programa/app que coleta dados ou exibe anuncios indevidos.",
        "actions": [
            "Remova programas desconhecidos e extensoes suspeitas do dispositivo.",
            "Ative bloqueio de anuncios/rastreadores na filtragem de DNS.",
        ],
    },
    {
        "match": ["mobile", "android", "ios"],
        "title": "Ameaca em dispositivo movel",
        "risk": "medio",
        "what": "Assinatura relacionada a malware ou comportamento suspeito em celular/tablet.",
        "means": "Um app instalado no dispositivo movel pode ser malicioso.",
        "actions": ["Revise apps instalados recentemente; remova os de fontes desconhecidas."],
    },
    {
        "match": ["scada", "ics", "modbus", "iot", "voip", "sip"],
        "title": "Protocolos industriais / IoT / VoIP",
        "risk": "medio",
        "what": "Trafego suspeito em protocolos de automacao, dispositivos IoT ou VoIP.",
        "means": "Dispositivos IoT costumam ter firmware fraco e sao alvos frequentes. Pode ser tentativa de acesso ou uso indevido.",
        "actions": [
            "Coloque dispositivos IoT em uma rede/VLAN separada e isolada.",
            "Atualize o firmware dos dispositivos e troque senhas padrao.",
        ],
    },
    {
        "match": ["compromised", "ciarmy", "dshield", "spamhaus", "drop", "blocklist", "reputation", "known bad", "tor exit"],
        "title": "Comunicacao com IP de ma reputacao",
        "risk": "medio",
        "what": "Conexao com endereco listado em blocklists publicas (hosts comprometidos, atacantes conhecidos, spam, saida TOR).",
        "means": "Se a conexao foi iniciada de fora, e um atacante conhecido batendo na porta (normal e bloqueado). Se um dispositivo interno iniciou a conexao, ele pode estar comprometido ou usando um servico hospedado em infraestrutura suspeita.",
        "actions": [
            "Verifique a direcao: bloqueado vindo de fora = ok. Saindo de dentro = investigar o dispositivo.",
            "Mantenha as categorias de blocklist ativas no IPS.",
        ],
    },
    {
        "match": ["ftp", "telnet", "smb", "netbios", "rdp", "ssh", "brute", "bruteforce", "login"],
        "title": "Forca bruta / Acesso a servicos administrativos",
        "risk": "alto",
        "what": "Tentativas repetidas de login ou acesso a servicos como SSH, RDP, SMB, Telnet, FTP.",
        "means": "Alguem esta tentando adivinhar senhas de um servico. Se o servico esta exposto na internet, e questao de tempo ate uma senha fraca cair.",
        "actions": [
            "Nunca exponha RDP/SMB/Telnet/FTP diretamente na internet; use VPN (WireGuard/Teleport) para acesso remoto.",
            "Use senhas fortes/chaves SSH e ative 2FA onde possivel.",
            "Restrinja acesso por regiao e habilite bloqueio de IP apos falhas.",
        ],
    },
]

DEFAULT_CATEGORY = {
    "title": "Assinatura de seguranca generica",
    "risk": "medio",
    "what": "Trafego que corresponde a uma regra do IDS/IPS (Suricata/Emerging Threats).",
    "means": "O padrao de pacotes coincide com uma assinatura de atividade suspeita. Nem toda deteccao e um ataque real (falsos positivos existem), mas vale entender a origem e o destino.",
    "actions": [
        "Verifique se a origem e interna ou externa.",
        "Pesquise o nome exato da assinatura (ex.: no site de regras ET) para detalhes.",
        "Se se repetir com o mesmo dispositivo interno, investigue-o.",
    ],
}

SEVERITY_MAP = {1: ("alto", "Alta"), 2: ("medio", "Media"), 3: ("baixo", "Baixa"), 4: ("baixo", "Informativa")}
RISK_ORDER = {"critico": 4, "alto": 3, "medio": 2, "baixo": 1}


def is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


_ET_CLASS = re.compile(r"^(?:ET|ETPRO|GPL|SURICATA)\s+([A-Z_]+)\b")


def _pick(text: str) -> dict | None:
    best = None
    for cat in CATEGORIES:
        if any(m in text for m in cat["match"]) and (best is None or RISK_ORDER[cat["risk"]] > RISK_ORDER[best["risk"]]):
            best = cat
    return best


def classify(signature: str, category: str, catname: str = "") -> dict:
    # A classe da regra Emerging Threats ("ET SCAN ...", "ET MALWARE ...") e o indicador mais preciso.
    m = _ET_CLASS.match(signature or "")
    if m:
        hit = _pick(m.group(1).lower().replace("_", " "))
        if hit:
            return hit
    for text in (catname or "", category or "", signature or ""):
        hit = _pick(text.lower())
        if hit:
            return hit
    return DEFAULT_CATEGORY


def _direction(src: str | None, dst: str | None) -> tuple[str, str]:
    si, di = is_private(src), is_private(dst)
    if si and not di:
        return "saida", "Iniciado por um dispositivo INTERNO em direcao a internet."
    if di and not si:
        return "entrada", "Vindo da INTERNET em direcao a um dispositivo interno."
    if si and di:
        return "interno", "Trafego entre dois dispositivos da rede interna (movimento lateral)."
    return "externo", "Entre enderecos externos (ex.: trafego roteado ou IPv6)."


def explain_event(ev: dict, clients_by_ip: dict[str, dict] | None = None) -> dict:
    """Transforma um evento bruto do IPS em uma explicacao detalhada."""
    clients_by_ip = clients_by_ip or {}
    sig = ev.get("inner_alert_signature") or ev.get("msg") or ev.get("key") or ""
    cat = ev.get("inner_alert_category") or ""
    catname = ev.get("catname") or ""
    sev = ev.get("inner_alert_severity")
    action = (ev.get("inner_alert_action") or ev.get("action") or "").lower()
    src, dst = ev.get("src_ip"), ev.get("dest_ip")
    sport, dport = ev.get("src_port"), ev.get("dest_port")
    proto = ev.get("proto") or ev.get("app_proto") or ""
    info = classify(sig, cat, catname)
    direction, direction_text = _direction(src, dst)

    risk = info["risk"]
    sev_key, sev_label = SEVERITY_MAP.get(int(sev) if sev is not None else 0, (None, "Desconhecida"))
    if sev_key and RISK_ORDER[sev_key] > RISK_ORDER[risk]:
        risk = sev_key
    if direction == "saida" and risk in ("medio", "baixo") and info["title"].startswith(("Malware", "Comunicacao")):
        risk = "alto"

    blocked = action in ("blocked", "drop", "dropped", "reject")
    internal_ip = src if is_private(src) else (dst if is_private(dst) else None)
    internal_client = clients_by_ip.get(internal_ip or "", {})
    country = ev.get("srcipCountry") or ev.get("src_ip_country") or ev.get("srcipGeo", {}).get("country_name") if isinstance(ev.get("srcipGeo"), dict) else ev.get("srcipCountry")
    dcountry = ev.get("dstipCountry") or (ev.get("dstipGeo", {}).get("country_name") if isinstance(ev.get("dstipGeo"), dict) else None)

    summary_parts = [f"{info['title']}."]
    summary_parts.append(direction_text)
    if blocked:
        summary_parts.append("O IPS BLOQUEOU a conexao - a ameaca foi contida.")
    else:
        summary_parts.append("O trafego foi apenas DETECTADO (nao bloqueado). Se o IPS estiver em modo 'Notificar', considere mudar para 'Prevenir'.")

    steps = list(info["actions"])
    if internal_ip:
        who = internal_client.get("name") or internal_client.get("hostname") or "dispositivo desconhecido"
        steps.insert(0, f"Dispositivo interno envolvido: {who} ({internal_ip}). Confirme o que ele estava fazendo no horario do evento.")

    m = re.search(r"CVE-\d{4}-\d+", sig, re.IGNORECASE)
    cve = m.group(0).upper() if m else None

    return {
        "id": ev.get("_id") or ev.get("id"),
        "time": ev.get("time") or ev.get("timestamp"),
        "datetime": ev.get("datetime"),
        "signature": sig,
        "signatureId": ev.get("inner_alert_signature_id") or ev.get("signature_id"),
        "category": cat,
        "categoryUnifi": catname,
        "severity": sev,
        "severityLabel": sev_label,
        "risk": risk,
        "title": info["title"],
        "what": info["what"],
        "means": info["means"],
        "direction": direction,
        "directionText": direction_text,
        "blocked": blocked,
        "action": action or "detectado",
        "src": {"ip": src, "port": sport, "country": country, "internal": is_private(src)},
        "dst": {"ip": dst, "port": dport, "country": dcountry, "internal": is_private(dst)},
        "proto": proto,
        "appProto": ev.get("app_proto"),
        "internalDevice": {
            "ip": internal_ip,
            "name": internal_client.get("name") or internal_client.get("hostname"),
            "mac": internal_client.get("mac") or internal_client.get("macAddress"),
        } if internal_ip else None,
        "cve": cve,
        "cveUrl": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None,
        "summary": " ".join(summary_parts),
        "steps": steps,
        "raw": ev,
    }


def summarize(explained: list[dict]) -> dict:
    by_risk: dict[str, int] = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
    by_title: dict[str, int] = {}
    by_src: dict[str, int] = {}
    by_internal: dict[str, dict] = {}
    by_country: dict[str, int] = {}
    blocked = 0
    for e in explained:
        by_risk[e["risk"]] = by_risk.get(e["risk"], 0) + 1
        by_title[e["title"]] = by_title.get(e["title"], 0) + 1
        if e["src"]["ip"] and not e["src"]["internal"]:
            by_src[e["src"]["ip"]] = by_src.get(e["src"]["ip"], 0) + 1
        if e["internalDevice"] and e["internalDevice"]["ip"]:
            ip = e["internalDevice"]["ip"]
            d = by_internal.setdefault(ip, {"ip": ip, "name": e["internalDevice"]["name"], "count": 0, "maxRisk": "baixo"})
            d["count"] += 1
            if RISK_ORDER[e["risk"]] > RISK_ORDER[d["maxRisk"]]:
                d["maxRisk"] = e["risk"]
        c = e["src"].get("country")
        if c and not e["src"]["internal"]:
            by_country[c] = by_country.get(c, 0) + 1
        if e["blocked"]:
            blocked += 1
    top = lambda d, n=10: sorted(d.items(), key=lambda kv: -kv[1])[:n]
    return {
        "total": len(explained),
        "blocked": blocked,
        "detectedOnly": len(explained) - blocked,
        "byRisk": by_risk,
        "byType": [{"title": k, "count": v} for k, v in top(by_title)],
        "topSources": [{"ip": k, "count": v} for k, v in top(by_src)],
        "topCountries": [{"country": k, "count": v} for k, v in top(by_country)],
        "internalDevices": sorted(by_internal.values(), key=lambda d: (-RISK_ORDER[d["maxRisk"]], -d["count"]))[:10],
    }


# --------------------------------------------------- eventos gerais do sistema
EVENT_KEYS = {
    "EVT_WU_Connected": ("Cliente WiFi conectou", "info"),
    "EVT_WU_Disconnected": ("Cliente WiFi desconectou", "info"),
    "EVT_WU_Roam": ("Cliente WiFi migrou de AP (roaming)", "info"),
    "EVT_WU_RoamRadio": ("Cliente WiFi trocou de banda", "info"),
    "EVT_LU_Connected": ("Cliente cabeado conectou", "info"),
    "EVT_LU_Disconnected": ("Cliente cabeado desconectou", "info"),
    "EVT_WG_Connected": ("Convidado WiFi conectou", "info"),
    "EVT_WG_AuthorizationEnded": ("Autorizacao de convidado expirou", "info"),
    "EVT_AP_Connected": ("Access Point ficou online", "info"),
    "EVT_AP_Lost_Contact": ("Access Point perdeu contato", "alerta"),
    "EVT_AP_Restarted": ("Access Point reiniciou", "alerta"),
    "EVT_AP_RestartedUnknown": ("Access Point reiniciou inesperadamente", "alerta"),
    "EVT_AP_Upgraded": ("Firmware do AP atualizado", "info"),
    "EVT_AP_Adopted": ("Access Point adotado", "info"),
    "EVT_AP_DetectRogueAP": ("AP nao autorizado (rogue) detectado", "seguranca"),
    "EVT_SW_Connected": ("Switch ficou online", "info"),
    "EVT_SW_Lost_Contact": ("Switch perdeu contato", "alerta"),
    "EVT_SW_Restarted": ("Switch reiniciou", "alerta"),
    "EVT_SW_Upgraded": ("Firmware do switch atualizado", "info"),
    "EVT_SW_PoeDisconnect": ("Dispositivo PoE desconectado", "alerta"),
    "EVT_SW_StpPortBlocking": ("Porta bloqueada pelo STP (possivel loop)", "alerta"),
    "EVT_GW_Connected": ("Gateway ficou online", "info"),
    "EVT_GW_Lost_Contact": ("Gateway perdeu contato", "critico"),
    "EVT_GW_Restarted": ("Gateway reiniciou", "alerta"),
    "EVT_GW_Upgraded": ("Firmware do gateway atualizado", "info"),
    "EVT_GW_WANTransition": ("Transicao de WAN (failover)", "alerta"),
    "EVT_GW_WANDown": ("Link WAN caiu", "critico"),
    "EVT_GW_WANUp": ("Link WAN voltou", "info"),
    "EVT_IPS_IpsAlert": ("Alerta do IPS (ameaca detectada)", "seguranca"),
    "EVT_IPS_IpsAlertBlocked": ("Ameaca bloqueada pelo IPS", "seguranca"),
    "EVT_AD_Login": ("Login de administrador", "seguranca"),
    "EVT_AD_LoginFailed": ("Falha de login de administrador", "seguranca"),
    "EVT_AD_Logout": ("Logout de administrador", "info"),
    "EVT_HS_VoucherCreated": ("Voucher de hotspot criado", "info"),
    "EVT_DM_Upgrade": ("Atualizacao do UniFi OS", "info"),
    "EVT_GW_RadiusAuthFailed": ("Falha de autenticacao RADIUS", "seguranca"),
    "EVT_WU_BlockedByFirewall": ("Cliente bloqueado pelo firewall", "seguranca"),
    "EVT_LU_BlockedByFirewall": ("Cliente bloqueado pelo firewall", "seguranca"),
    "EVT_AP_ChannelChanged": ("Canal WiFi alterado", "info"),
    "EVT_AP_RADAR_Detected": ("Radar detectado (DFS) - canal alterado", "info"),
}


def explain_system_event(ev: dict) -> dict:
    key = ev.get("key", "")
    title, kind = EVENT_KEYS.get(key, (key.replace("EVT_", "").replace("_", " "), "info"))
    if kind == "info" and key not in EVENT_KEYS:
        if "Lost" in key or "Down" in key or "Failed" in key:
            kind = "alerta"
        if "IPS" in key or "Rogue" in key or "Block" in key or "Login" in key:
            kind = "seguranca"
    return {
        "id": ev.get("_id"),
        "time": ev.get("time"),
        "datetime": ev.get("datetime"),
        "key": key,
        "title": title,
        "kind": kind,
        "subsystem": ev.get("subsystem"),
        "message": ev.get("msg"),
        "user": ev.get("user") or ev.get("hostname") or ev.get("client"),
        "device": ev.get("ap_name") or ev.get("sw_name") or ev.get("gw_name") or ev.get("ap") or ev.get("sw") or ev.get("gw"),
        "ssid": ev.get("ssid"),
        "network": ev.get("network"),
        "ip": ev.get("ip"),
        "admin": ev.get("admin"),
        "raw": ev,
    }


ALARM_HINTS = {
    "EVT_AP_Lost_Contact": "Verifique cabo/PoE do AP e se o switch esta online.",
    "EVT_SW_Lost_Contact": "Verifique alimentacao e uplink do switch.",
    "EVT_GW_WANDown": "Verifique o modem/ONU do provedor e o cabo da porta WAN.",
    "EVT_IPS_IpsAlert": "Abra a aba Ameacas para a explicacao detalhada.",
    "EVT_AD_LoginFailed": "Varias falhas seguidas indicam tentativa de forca bruta contra o painel do UniFi. Restrinja o acesso remoto e ative 2FA na conta UI.",
}
