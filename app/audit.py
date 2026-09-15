"""Motor de auditoria de seguranca e configuracao guiada.

Cada verificacao produz um "finding" com:
  id, severity (critico|alto|medio|baixo|ok|info), title, detail (o que foi
  encontrado), why (por que importa), manual (passos na interface do UniFi) e,
  quando possivel, `fix` = acao automatica que o painel consegue aplicar via API.
"""
from __future__ import annotations

import re
from typing import Any

from .unifi_client import UniFiClient, UniFiError

SEV_ORDER = {"critico": 5, "alto": 4, "medio": 3, "baixo": 2, "info": 1, "ok": 0}
IOT_HINTS = re.compile(r"iot|camera|cam|smart|tv|alexa|guest|convidad|visitant|dmz|server|servidor|ap\b", re.IGNORECASE)
GUEST_HINTS = re.compile(r"guest|convidad|visitant|hotspot", re.IGNORECASE)
CAM_HINTS = re.compile(r"camera|cam|cctv|protect|uvc|g3|g4|g5|ai-pro|flex|bullet|dome|turret|nvr", re.IGNORECASE)
U6_HINTS = re.compile(r"u6|u6lr|u6-lr|u6-pro|u6-plus|u6-enterprise|u6-mesh|u6-iw|u7", re.IGNORECASE)


def _f(id_: str, severity: str, title: str, detail: str, why: str = "", manual: list[str] | None = None,
       fix: dict | None = None, area: str = "geral", refs: list[dict] | None = None) -> dict:
    return {
        "id": id_, "severity": severity, "title": title, "detail": detail, "why": why,
        "manual": manual or [], "fix": fix, "area": area, "refs": refs or [],
    }


class SecurityAudit:
    def __init__(self, c: UniFiClient):
        self.c = c
        self.findings: list[dict] = []
        self.errors: list[str] = []
        self.data: dict[str, Any] = {}

    # ------------------------------------------------------------ coleta
    def _safe(self, name: str, fn, default=None):
        try:
            v = fn()
            self.data[name] = v
            return v
        except UniFiError as e:
            self.errors.append(f"{name}: {e}")
            self.data[name] = default
            return default

    def run(self) -> dict:
        c = self.c
        self._safe("devices", c.devices, [])
        self._safe("clients", c.clients, [])
        self._safe("networks", c.networks, [])
        self._safe("wifi", c.wifi, [])
        self._safe("zones", c.firewall_zones, [])
        self._safe("policies", c.firewall_policies, [])
        self._safe("vpn", c.vpn_servers, [])
        self._safe("pending", c.pending_devices, [])
        # detalhes de redes/wifi (config de seguranca so vem no detalhe)
        nets = []
        for n in self.data["networks"] or []:
            d = self._safe(f"network:{n.get('id')}", lambda n=n: c.network(n["id"]), n)
            nets.append(d or n)
        self.data["networks_detail"] = nets
        wifis = []
        for w in self.data["wifi"] or []:
            d = self._safe(f"wifi:{w.get('id')}", lambda w=w: c.wifi_detail(w["id"]), w)
            wifis.append(d or w)
        self.data["wifi_detail"] = wifis

        classic = c.classic_available()
        self.data["classic"] = classic
        if classic:
            self._safe("settings", c.settings, [])
            self._safe("alarms", lambda: c.alarms(200), [])
            self._safe("events", lambda: c.events(500, 72), [])
            self._safe("ips_events", lambda: c.ips_events(500), [])

        self.check_ips()
        self.check_wifi()
        self.check_u6_aps()
        self.check_networks()
        self.check_cameras_protect()
        self.check_firewall()
        self.check_devices()
        self.check_udm_pro_hardware()
        self.check_vpn()
        self.check_gateway_settings()
        self.check_admin_activity()
        self.check_clients()

        self.findings.sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
        score = self.score()
        return {
            "score": score,
            "grade": grade(score),
            "counts": {k: sum(1 for f in self.findings if f["severity"] == k) for k in SEV_ORDER},
            "findings": self.findings,
            "errors": self.errors,
            "classicApi": classic,
        }

    def score(self) -> int:
        penalty = {"critico": 25, "alto": 12, "medio": 6, "baixo": 2, "info": 0, "ok": 0}
        s = 100 - sum(penalty[f["severity"]] for f in self.findings)
        return max(0, min(100, s))

    def _setting(self, key: str) -> dict:
        for s in self.data.get("settings") or []:
            if s.get("key") == key:
                return s
        return {}

    # ------------------------------------------------------------- checks
    def check_ips(self):
        if not self.data.get("classic"):
            self.findings.append(_f(
                "ips-unknown", "info", "Estado do IDS/IPS nao pode ser lido",
                "A API classica nao esta acessivel com esta chave/conexao; a configuracao do IPS nao pode ser verificada automaticamente.",
                "O IDS/IPS e a principal defesa contra ameacas conhecidas.",
                ["Settings > Security > Intrusion Prevention: escolha 'Prevent' (Prevenir) e ative todas as categorias relevantes."],
                area="ameacas"))
            return
        ips = self._setting("ips")
        mode = (ips.get("ips_mode") or "disabled").lower()
        cats = ips.get("enabled_categories") or []
        if mode in ("disabled", "off", ""):
            self.findings.append(_f(
                "ips-off", "critico", "IDS/IPS desativado",
                "O sistema de deteccao/prevencao de intrusao esta desligado. Nenhuma ameaca sera detectada ou bloqueada.",
                "Sem IPS, malware, exploits e varreduras passam sem qualquer alerta.",
                ["Settings > Security > Intrusion Prevention > selecione 'Prevent'.", "Ative as categorias: Malware, Botnet, Exploits, Scans, Blocklists."],
                fix={"action": "set_ips_mode", "params": {"mode": "ips"}, "label": "Ativar IPS em modo Prevenir"}, area="ameacas"))
        elif mode == "ids":
            self.findings.append(_f(
                "ips-detect-only", "alto", "IPS em modo 'Notificar' (somente deteccao)",
                "Ameacas sao registradas, mas NAO bloqueadas.",
                "O modo IDS apenas avisa; um ataque em andamento continua ate ser bloqueado manualmente.",
                ["Settings > Security > Intrusion Prevention > mude de 'Notify' para 'Prevent'."],
                fix={"action": "set_ips_mode", "params": {"mode": "ips"}, "label": "Mudar para modo Prevenir (bloquear)"}, area="ameacas"))
        else:
            self.findings.append(_f("ips-ok", "ok", "IPS ativo em modo Prevenir", f"Categorias ativas: {len(cats)}.", area="ameacas"))
        if mode != "disabled" and len(cats) < 8:
            self.findings.append(_f(
                "ips-few-cats", "medio", "Poucas categorias de ameaca ativas no IPS",
                f"Apenas {len(cats)} categorias habilitadas: {', '.join(cats) or 'nenhuma'}.",
                "Categorias desativadas nao geram deteccao. Recomenda-se ao menos: emerging-malware, emerging-botcc, emerging-exploit, emerging-scan, emerging-dos, emerging-trojan, emerging-worm, botcc, ciarmy, compromised, dshield, drop, tor, emerging-attackresponse, emerging-shellcode, emerging-webserver.",
                ["Settings > Security > Intrusion Prevention > Categories: marque as categorias recomendadas."],
                fix={"action": "set_ips_categories", "params": {}, "label": "Ativar conjunto recomendado de categorias"}, area="ameacas"))
        if not ips.get("ad_blocking_enabled"):
            self.findings.append(_f(
                "ips-adblock", "baixo", "Bloqueio de anuncios/rastreadores desativado",
                "Ad blocking (filtragem de DNS) esta desligado.",
                "Reduz malvertising, rastreadores e alguns dominios de phishing para toda a rede.",
                ["Settings > Security > Ad Blocking: ative e selecione as redes."],
                fix={"action": "set_ips_flag", "params": {"field": "ad_blocking_enabled", "value": True}, "label": "Ativar bloqueio de anuncios"}, area="ameacas"))
        if not ips.get("restrict_tor"):
            self.findings.append(_f(
                "ips-tor", "baixo", "Trafego TOR nao esta restrito",
                "Dispositivos podem usar a rede TOR, que oculta destino do trafego (usado por malware e para burlar controles).",
                manual=["Settings > Security > Traffic Restriction: ative 'Restrict access to Tor'."],
                fix={"action": "set_ips_flag", "params": {"field": "restrict_tor", "value": True}, "label": "Restringir TOR"}, area="ameacas"))
        if not ips.get("restrict_torrents"):
            self.findings.append(_f(
                "ips-torrent", "info", "Torrents/P2P permitidos",
                "P2P nao esta bloqueado. Se nao for necessario, bloquear reduz exposicao a arquivos maliciosos e uso de banda.",
                manual=["Settings > Security > Traffic Restriction: ative 'Restrict BitTorrent'."],
                fix={"action": "set_ips_flag", "params": {"field": "restrict_torrents", "value": True}, "label": "Bloquear torrents"}, area="ameacas"))
        if not ips.get("honeypot_enabled"):
            self.findings.append(_f(
                "ips-honeypot", "info", "Honeypot desativado",
                "O honeypot e um servico-isca que alerta quando algo na rede interna tenta acessa-lo - otimo para detectar movimento lateral.",
                manual=["Settings > Security > Internal Honeypot: ative e escolha um IP livre em cada rede."], area="ameacas"))
        # eventos nao bloqueados
        evs = self.data.get("ips_events") or []
        not_blocked = [e for e in evs if (e.get("inner_alert_action") or "").lower() not in ("blocked", "drop", "dropped")]
        if evs and len(not_blocked) > 0:
            self.findings.append(_f(
                "ips-unblocked", "alto" if len(not_blocked) > 20 else "medio",
                f"{len(not_blocked)} ameacas detectadas mas nao bloqueadas (7 dias)",
                f"De {len(evs)} eventos do IPS, {len(not_blocked)} passaram sem bloqueio.",
                "Deteccao sem bloqueio significa que o trafego malicioso chegou ao destino.",
                ["Veja a aba Ameacas para detalhes de cada evento.", "Coloque o IPS em modo Prevenir e revise as categorias."], area="ameacas"))

    def check_wifi(self):
        for w in self.data.get("wifi_detail") or []:
            if not w.get("enabled"):
                continue
            name = w.get("name", "?")
            sec = (w.get("securityConfiguration") or {})
            st = sec.get("type", "?")
            ref = [{"type": "wifi", "id": w.get("id"), "name": name}]
            if st == "OPEN":
                hotspot = bool(w.get("hotspotConfiguration"))
                self.findings.append(_f(
                    f"wifi-open-{w['id']}", "medio" if hotspot else "critico", f"WiFi '{name}' sem senha (aberta)",
                    "Rede aberta: qualquer pessoa no alcance conecta e o trafego nao e criptografado." + (" Possui portal de hotspot." if hotspot else ""),
                    "Sem criptografia, o trafego pode ser capturado e a rede usada por estranhos.",
                    ["Settings > WiFi > (rede) > Security: escolha WPA2/WPA3 e defina uma senha forte.", "Se for rede de convidados, ative 'Client Device Isolation' e use um Hotspot Portal."],
                    area="wifi", refs=ref))
            elif st == "WPA2_PERSONAL":
                self.findings.append(_f(
                    f"wifi-wpa2-{w['id']}", "baixo", f"WiFi '{name}' usa apenas WPA2",
                    "WPA2 ainda e aceitavel, mas WPA2/WPA3 (modo misto) adiciona protecao contra ataques de dicionario offline (SAE) mantendo compatibilidade.",
                    manual=["Settings > WiFi > (rede) > Security Protocol: 'WPA2/WPA3'."], area="wifi", refs=ref))
            if sec.get("pmfMode") is None and st in ("WPA2_PERSONAL", "WPA2_WPA3_PERSONAL", "WPA2_ENTERPRISE"):
                self.findings.append(_f(
                    f"wifi-pmf-{w['id']}", "info", f"WiFi '{name}' sem PMF (Protected Management Frames)",
                    "PMF protege contra ataques de desautenticacao (derrubar clientes a forca).",
                    manual=["Settings > WiFi > (rede) > Advanced > PMF: 'Optional' (ou 'Required' se todos os clientes suportarem)."], area="wifi", refs=ref))
            if GUEST_HINTS.search(name) and not w.get("clientIsolationEnabled"):
                self.findings.append(_f(
                    f"wifi-iso-{w['id']}", "medio", f"WiFi de convidados '{name}' sem isolamento de clientes",
                    "Convidados conseguem enxergar uns aos outros e potencialmente outros dispositivos.",
                    manual=["Settings > WiFi > (rede) > Advanced > ative 'Client Device Isolation'."],
                    fix={"action": "wifi_client_isolation", "params": {"wifiId": w["id"]}, "label": "Ativar isolamento de clientes"}, area="wifi", refs=ref))
            passphrase = sec.get("passphrase")
            if passphrase and len(passphrase) < 12:
                self.findings.append(_f(
                    f"wifi-pass-{w['id']}", "alto", f"Senha curta na WiFi '{name}'",
                    f"A senha tem apenas {len(passphrase)} caracteres.",
                    "Senhas curtas de WiFi sao quebradas offline em minutos com GPUs.",
                    ["Use 16+ caracteres com palavras aleatorias ou frase longa."], area="wifi", refs=ref))

    def check_u6_aps(self):
        """Verificacoes de otimizacao especificas para antenas UniFi U6 e U6-LR (Wi-Fi 6)."""
        devs = self.data.get("devices") or []
        u6_aps = [d for d in devs if U6_HINTS.search(d.get("model", "")) or U6_HINTS.search(d.get("name", ""))]
        if not u6_aps:
            return

        for ap in u6_aps:
            name = ap.get("name", ap.get("model", "AP U6"))
            ref = [{"type": "device", "id": ap.get("id"), "name": name}]
            # detalhes/interfaces do AP
            stats = self._safe(f"device:{ap['id']}", lambda ap=ap: self.c.device(ap["id"]), ap)
            radios = ((stats or {}).get("interfaces") or {}).get("radios") or []
            r5ghz = next((r for r in radios if r.get("frequencyGHz") in (5, 6)), None)
            if r5ghz:
                width = r5ghz.get("channelWidthMHz", 20)
                if width < 80:
                    self.findings.append(_f(
                        f"u6-width-{ap['id']}", "medio", f"AP Wi-Fi 6 '{name}' operando em largura subotimizada ({width}MHz em 5GHz)",
                        f"O AP Wi-Fi 6 ({ap.get('model')}) suporta 80MHz/160MHz, mas esta configurado em {width}MHz.",
                        "Larguras de 20MHz/40MHz no 5GHz limitam drasticamente a throughput de alta velocidade do Wi-Fi 6 (OFDMA/MU-MIMO).",
                        ["UniFi Devices > (AP) > Settings > Radios > 5GHz Channel Width: selecione HE80 ou HE160."],
                        area="wifi", refs=ref))
                else:
                    self.findings.append(_f(f"u6-width-ok-{ap['id']}", "ok", f"AP Wi-Fi 6 '{name}' com largura otimizada ({width}MHz)", "High-throughput Wi-Fi 6 ativo.", area="wifi", refs=ref))

        # PMF e WPA3 global para radios U6
        for w in self.data.get("wifi_detail") or []:
            if not w.get("enabled"):
                continue
            sec = w.get("securityConfiguration") or {}
            st = sec.get("type", "")
            if st == "WPA2_PERSONAL":
                self.findings.append(_f(
                    f"u6-wpa3-upgrade-{w['id']}", "info", f"Rede WiFi '{w.get('name')}' nao aproveita WPA3/SAE nos APs U6",
                    "A rede esta configurada apenas em WPA2. Os APs UniFi U6-LR / U6 suportam WPA2/WPA3 Personal (SAE) nativamente.",
                    "Ativar WPA2/WPA3 Misto melhora a seguranca contra brute-force sem desconectar dispositivos mais antigos.",
                    manual=["Settings > WiFi > (Rede) > Security Protocol: selecione WPA2/WPA3 Personal."],
                    fix={"action": "wifi_enable_wpa3", "params": {"wifiId": w["id"]}, "label": "Mudar para WPA2/WPA3 Misto"},
                    area="wifi"))

    def check_networks(self):
        nets = [n for n in (self.data.get("networks_detail") or []) if n.get("enabled", True)]
        gw_nets = [n for n in nets if n.get("management") == "GATEWAY"]
        if len(gw_nets) <= 1:
            self.findings.append(_f(
                "net-flat", "medio", "Rede sem segmentacao (apenas uma rede/VLAN)",
                "Todos os dispositivos (computadores, cameras, IoT, TVs, convidados) compartilham a mesma rede.",
                "Um dispositivo IoT comprometido tem acesso direto a computadores e servidores. Segmentar limita o estrago.",
                ["Settings > Networks > New: crie 'IoT' (VLAN 20) e 'Guest' (VLAN 30) com 'Isolate Network' ou zonas de firewall dedicadas.",
                 "Crie WiFis separadas apontando para essas redes.",
                 "Depois, use a aba Firewall deste painel para criar politicas de bloqueio entre zonas."],
                area="redes"))
        for n in gw_nets:
            name = n.get("name", "?")
            ref = [{"type": "network", "id": n.get("id"), "name": name}]
            if IOT_HINTS.search(name) and not n.get("default") and not n.get("isolationEnabled"):
                self.findings.append(_f(
                    f"net-iso-{n['id']}", "medio", f"Rede '{name}' nao esta isolada",
                    "Pelo nome, parece uma rede de IoT/cameras/convidados, mas 'Network Isolation' esta desligado.",
                    "Dispositivos dessa rede podem alcancar suas redes principais.",
                    ["Settings > Networks > (rede) > Advanced > ative 'Isolate Network' (ou crie politica de firewall bloqueando destino para redes internas)."],
                    fix={"action": "isolate_network", "params": {"networkId": n["id"]}, "label": "Ativar isolamento desta rede"}, area="redes", refs=ref))
            if not n.get("dhcpGuarding"):
                self.findings.append(_f(
                    f"net-dhcpg-{n['id']}", "info", f"DHCP Guarding desativado em '{name}'",
                    "Qualquer dispositivo pode se passar por servidor DHCP (rogue DHCP) e redirecionar trafego.",
                    manual=["Settings > Networks > (rede) > DHCP > DHCP Guarding: informe o IP do gateway como servidor confiavel."],
                    fix={"action": "dhcp_guarding", "params": {"networkId": n["id"]}, "label": "Ativar DHCP Guarding"}, area="redes", refs=ref))

    def check_cameras_protect(self):
        """Verificacoes de seguranca para Câmeras de Seguranca e UniFi Protect."""
        nets = [n for n in (self.data.get("networks_detail") or []) if n.get("enabled", True)]
        clients = self.data.get("clients") or []
        cam_nets = [n for n in nets if CAM_HINTS.search(n.get("name", ""))]
        cam_clients = [c for c in clients if CAM_HINTS.search(c.get("name", "") or "") or CAM_HINTS.search((c.get("extra") or {}).get("hostname", "") or "")]

        if not cam_nets and not cam_clients:
            self.findings.append(_f(
                "cam-vlan-missing", "info", "Nenhuma rede ou VLAN dedicada para Câmeras / CFTV detectada",
                "Câmeras de seguranca estao compartilhando a rede principal ou nao foram identificadas em uma VLAN própria.",
                "Câmeras IP sao alvos prioritarios para botnets (como Mirai) e invasores. Devem ser mantidas em VLAN isolada sem acesso a internet.",
                ["Settings > Networks > Create New Network: 'Câmeras / CFTV' (VLAN isolada).",
                 "Desative o acesso a internet ('Internet Access = Disabled') para a rede de câmeras."],
                area="cameras"))
            return

        for cn in cam_nets:
            ref = [{"type": "network", "id": cn["id"], "name": cn["name"]}]
            if cn.get("internetAccessEnabled", True):
                self.findings.append(_f(
                    f"cam-net-wan-{cn['id']}", "alto", f"Rede de Câmeras '{cn['name']}' possui acesso a Internet liberado",
                    "Câmeras de seguranca nao devem ter acesso livre a internet de saida para evitar exfiltracao de imagem e controle por botnets.",
                    "O UniFi Protect no UDM Pro gerencia o fluxo localmente; as câmeras IP nao precisam de acesso direto a WAN.",
                    ["Settings > Networks > (Rede Câmeras) > Advanced > desative 'Allow Internet Access'."],
                    fix={"action": "block_network_wan", "params": {"networkId": cn["id"]}, "label": "Bloquear Acesso a Internet da Rede de Câmeras"},
                    area="cameras", refs=ref))
            else:
                self.findings.append(_f(f"cam-net-wan-ok-{cn['id']}", "ok", f"Rede de Câmeras '{cn['name']}' sem acesso a Internet (Segura)", "Acesso WAN bloqueado para o segmento de CFTV.", area="cameras", refs=ref))

            if not cn.get("isolationEnabled"):
                self.findings.append(_f(
                    f"cam-net-iso-{cn['id']}", "medio", f"Rede de Câmeras '{cn['name']}' nao esta isolada (Network Isolation)",
                    "Dispositivos na rede de câmeras conseguem se comunicar diretamente com computadores e servidores internos.",
                    manual=["Settings > Networks > (Rede Câmeras) > Advanced > ative 'Isolate Network'."],
                    fix={"action": "isolate_network", "params": {"networkId": cn["id"]}, "label": "Isolar Rede de Câmeras"},
                    area="cameras", refs=ref))

            if not cn.get("dhcpGuarding"):
                self.findings.append(_f(
                    f"cam-net-dhcp-{cn['id']}", "info", f"DHCP Guarding desativado na rede de Câmeras '{cn['name']}'",
                    "Protege as portas dos switches conectadas as câmeras contra servidores DHCP falsos.",
                    manual=["Settings > Networks > (Rede Câmeras) > DHCP > DHCP Guarding: informe o IP do gateway."],
                    fix={"action": "dhcp_guarding", "params": {"networkId": cn["id"]}, "label": "Ativar DHCP Guarding na Rede de Câmeras"},
                    area="cameras", refs=ref))

    def check_firewall(self):
        zones = self.data.get("zones") or []
        pols = self.data.get("policies") or []
        user_pols = [p for p in pols if (p.get("metadata") or {}).get("origin") == "USER_DEFINED"]
        zone_names = {z["id"]: z["name"] for z in zones}
        self.data["zone_names"] = zone_names
        if not zones:
            self.findings.append(_f("fw-nozones", "info", "Zonas de firewall nao disponiveis",
                                    "O controlador nao retornou zonas (versao antiga sem Zone-Based Firewall?).", area="firewall"))
            return
        if not user_pols:
            self.findings.append(_f(
                "fw-nopolicies", "medio", "Nenhuma politica de firewall personalizada",
                "So existem as regras padrao do sistema. Redes internas normalmente se comunicam livremente entre si.",
                "Politicas explicitas (ex.: IoT -> Internal: bloquear) sao a base da segmentacao.",
                ["Use o assistente 'Criar politica de bloqueio' na aba Firewall deste painel.",
                 "Settings > Policy Engine / Firewall > Create Policy."], area="firewall"))
        for p in user_pols:
            act = (p.get("action") or {}).get("type")
            src = zone_names.get((p.get("source") or {}).get("zoneId"), "?")
            dst = zone_names.get((p.get("destination") or {}).get("zoneId"), "?")
            ref = [{"type": "policy", "id": p.get("id"), "name": p.get("name")}]
            if act == "ALLOW" and src.lower() == "external" and not (p.get("destination") or {}).get("trafficFilter"):
                self.findings.append(_f(
                    f"fw-ext-allow-{p['id']}", "critico", f"Politica '{p['name']}' permite External -> {dst} sem filtro",
                    "Uma regra ALLOW de origem Externa sem filtro de destino/porta abre a rede para a internet.",
                    "Equivale a desligar o firewall para essa zona.",
                    ["Edite a politica e restrinja por porta/IP, ou remova-a."],
                    fix={"action": "disable_policy", "params": {"policyId": p["id"]}, "label": "Desativar esta politica"}, area="firewall", refs=ref))
            if act in ("BLOCK", "REJECT") and not p.get("loggingEnabled"):
                self.findings.append(_f(
                    f"fw-log-{p['id']}", "info", f"Politica de bloqueio '{p['name']}' sem log",
                    f"{src} -> {dst}: bloqueios nao sao registrados; fica dificil investigar incidentes.",
                    manual=["Edite a politica > Advanced > 'Logging'."],
                    fix={"action": "policy_logging", "params": {"policyId": p["id"]}, "label": "Ativar log nesta politica"}, area="firewall", refs=ref))
            if not p.get("enabled"):
                self.findings.append(_f(f"fw-disabled-{p['id']}", "info", f"Politica '{p['name']}' desativada",
                                        f"{src} -> {dst} ({act}) esta desligada. Confirme se e intencional.", area="firewall", refs=ref))

    def check_devices(self):
        for d in self.data.get("devices") or []:
            ref = [{"type": "device", "id": d.get("id"), "name": d.get("name")}]
            if d.get("firmwareUpdatable"):
                self.findings.append(_f(
                    f"dev-fw-{d['id']}", "medio", f"Firmware desatualizado: {d.get('name')} ({d.get('model')})",
                    f"Versao atual {d.get('firmwareVersion')}. Ha atualizacao disponivel.",
                    "Atualizacoes corrigem vulnerabilidades conhecidas em APs, switches e gateway.",
                    ["UniFi Devices > (dispositivo) > Update."], area="dispositivos", refs=ref))
            if d.get("state") not in ("ONLINE", None):
                self.findings.append(_f(
                    f"dev-state-{d['id']}", "baixo", f"Dispositivo {d.get('name')} em estado {d.get('state')}",
                    "Dispositivo offline ou com problema de conexao.", area="dispositivos", refs=ref))
        pend = self.data.get("pending") or []
        if pend:
            self.findings.append(_f(
                "dev-pending", "info", f"{len(pend)} dispositivo(s) UniFi aguardando adocao",
                ", ".join(f"{p.get('model')} {p.get('macAddress')}" for p in pend[:5]),
                "Dispositivos nao adotados na sua rede podem ser de vizinhos ou equipamentos esquecidos.", area="dispositivos"))

    def check_udm_pro_hardware(self):
        """Auditoria especifica de otimizacao de hardware do UDM Pro (SFP+ e Protect)."""
        devs = self.data.get("devices") or []
        gw = next((d for d in devs if (d.get("features") or []).count("gateway") or "UDM" in (d.get("model") or "").upper()), None)
        if not gw:
            return

        gw_detail = self._safe(f"device:{gw['id']}", lambda gw=gw: self.c.device(gw["id"]), gw)
        ports = ((gw_detail or {}).get("interfaces") or {}).get("ports") or []
        ref = [{"type": "device", "id": gw["id"], "name": gw.get("name", "UDM Pro")}]

        # Inspeção das portas SFP+ 10G (Porta 10 WAN SFP+, Porta 11 LAN SFP+)
        sfp_ports = [p for p in ports if p.get("connector") in ("SFP+", "SFP") or p.get("maxSpeedMbps", 0) >= 10000 or p.get("idx") in (10, 11)]
        if sfp_ports:
            down_sfp = [p for p in sfp_ports if p.get("state") == "DOWN"]
            if len(down_sfp) == len(sfp_ports):
                self.findings.append(_f(
                    "udm-sfp-unused", "info", f"Portas SFP+ 10Gbps do {gw.get('model')} desaproveitadas",
                    "Nenhuma porta SFP+ 10G (Porta 10 WAN / Porta 11 LAN) esta conectada.",
                    "Usar a porta SFP+ 11 (DAC/Fibra) para interconectar o UDM Pro aos switches UniFi evita o gargalo de 1Gbps no backplane das portas RJ45 1-8.",
                    ["Utilize um cabo Direct Attach Copper (DAC) SFP+ 10G entre a Porta 11 do UDM Pro e a porta SFP+ do seu Switch principal."],
                    area="gateway", refs=ref))
            else:
                self.findings.append(_f("udm-sfp-ok", "ok", f"Porta SFP+ 10G ativa no {gw.get('model')}", "Interconexao de alta velocidade ativa.", area="gateway", refs=ref))

        # Status de armazenamento / NVR no UDM Pro
        nvr = self.c.protect_nvr()
        if nvr:
            for disk in nvr:
                status = disk.get("status") or disk.get("state") or "HEALTHY"
                if str(status).upper() not in ("OK", "HEALTHY", "GOOD"):
                    self.findings.append(_f(
                        f"udm-hdd-{disk.get('id', 'nvr')}", "alto", f"Alerta de saude no Disco / NVR do UDM Pro: {status}",
                        "O disco rígido interno do UDM Pro (usado pelo UniFi Protect) reportou estado anômalo.",
                        "Falha no disco pode interromper a gravacao contínua das câmeras de seguranca.",
                        ["Verifique o UniFi Storage / Protect settings no UDM Pro e substitua o HD se necessario."],
                        area="cameras", refs=ref))

    def check_vpn(self):
        for v in self.data.get("vpn") or []:
            if not v.get("enabled"):
                continue
            t = v.get("type")
            ref = [{"type": "vpn", "id": v.get("id"), "name": v.get("name")}]
            if t == "PPTP":
                self.findings.append(_f(
                    f"vpn-pptp-{v['id']}", "critico", f"Servidor VPN PPTP ativo ('{v.get('name')}')",
                    "PPTP e um protocolo quebrado (MS-CHAPv2 pode ser decifrado em horas).",
                    manual=["Migre para WireGuard ou Teleport e desative o PPTP em Settings > VPN."], area="vpn", refs=ref))
            elif t == "L2TP":
                self.findings.append(_f(
                    f"vpn-l2tp-{v['id']}", "medio", f"Servidor VPN L2TP/IPsec ativo ('{v.get('name')}')",
                    "L2TP com chave pre-compartilhada e aceitavel, mas WireGuard e mais seguro e rapido.",
                    manual=["Considere migrar para WireGuard (Settings > VPN > VPN Server)."], area="vpn", refs=ref))
            else:
                self.findings.append(_f(f"vpn-ok-{v['id']}", "ok", f"VPN {t} ativa ('{v.get('name')}')", "Protocolo moderno.", area="vpn", refs=ref))

    def check_gateway_settings(self):
        if not self.data.get("classic"):
            return
        usg = self._setting("usg")
        mgmt = self._setting("mgmt")
        if usg.get("upnp_enabled"):
            self.findings.append(_f(
                "gw-upnp", "alto", "UPnP ativado",
                "Qualquer aplicativo/dispositivo interno pode abrir portas na sua internet automaticamente, sem voce saber.",
                "Malware e dispositivos IoT usam UPnP para se expor a internet.",
                ["Settings > Internet > (WAN) > Advanced > desative UPnP.", "Se um jogo/console precisar, crie encaminhamento de porta manual e restrito."],
                fix={"action": "set_usg_flag", "params": {"field": "upnp_enabled", "value": False}, "label": "Desativar UPnP"}, area="gateway"))
        else:
            self.findings.append(_f("gw-upnp-ok", "ok", "UPnP desativado", "", area="gateway"))
        if not usg.get("geo_ip_filtering_enabled"):
            self.findings.append(_f(
                "gw-geoip", "baixo", "Restricao por pais (GeoIP) desativada",
                "Nenhum pais bloqueado. Bloquear regioes de onde voce nunca espera trafego reduz drasticamente varreduras e forca bruta.",
                manual=["Settings > Security > Country Restriction: bloqueie trafego de entrada de paises que nao usa."], area="gateway"))
        if mgmt.get("x_ssh_enabled"):
            self.findings.append(_f(
                "gw-ssh", "baixo", "SSH habilitado nos dispositivos UniFi",
                "Acesso SSH esta ativo. Util para diagnostico, mas amplia superficie de ataque se a senha for fraca.",
                manual=["Settings > System > Advanced > SSH: desative ou use chave forte."], area="gateway"))
        if usg.get("broadcast_ping"):
            self.findings.append(_f("gw-bping", "info", "Resposta a ping broadcast ativa", "Pode ser usada em ataques Smurf.", area="gateway"))
        if not usg.get("firewall_wan_default_log", False):
            self.findings.append(_f("gw-wanlog", "info", "Log padrao de WAN desativado",
                                    "Conexoes bloqueadas na WAN nao sao registradas.", manual=["Settings > Firewall > Advanced > Logging."], area="gateway"))

    def check_admin_activity(self):
        evs = self.data.get("events") or []
        fails = [e for e in evs if e.get("key") == "EVT_AD_LoginFailed"]
        if len(fails) >= 5:
            self.findings.append(_f(
                "adm-bruteforce", "alto", f"{len(fails)} falhas de login de administrador (72h)",
                "Muitas tentativas de login invalidas no painel do UniFi.",
                "Indica forca bruta contra a interface de administracao.",
                ["Nao exponha a porta 443 do UDM na internet; use o acesso remoto via unifi.ui.com ou VPN.", "Ative 2FA na conta Ubiquiti.", "Revise Settings > Admins."], area="admin"))
        rogue = [e for e in evs if e.get("key") == "EVT_AP_DetectRogueAP"]
        if rogue:
            self.findings.append(_f(
                "rogue-ap", "medio", f"{len(rogue)} deteccoes de AP nao autorizado",
                "Um ponto de acesso desconhecido esta anunciando um SSID igual/parecido com o seu ou conectado a sua rede cabeada.",
                "Pode ser um 'evil twin' para roubar senhas WiFi.",
                ["Insights > Neighboring Access Points: identifique o AP.", "Verifique se ha roteadores nao autorizados ligados em portas do switch."], area="wifi"))

    def check_clients(self):
        clients = self.data.get("clients") or []
        guests = [c for c in clients if (c.get("access") or {}).get("type") == "GUEST"]
        vpn = [c for c in clients if c.get("type") in ("VPN", "TELEPORT")]
        self.findings.append(_f(
            "clients-summary", "info", f"{len(clients)} clientes conectados",
            f"{len(guests)} convidado(s), {len(vpn)} via VPN/Teleport. Revise a aba Clientes para dispositivos desconhecidos.", area="clientes"))


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


# ------------------------------------------------------------ acoes guiadas
RECOMMENDED_IPS_CATEGORIES = [
    "emerging-attackresponse", "emerging-botcc", "botcc", "emerging-dos", "emerging-exploit", "emerging-malware",
    "emerging-scan", "emerging-shellcode", "emerging-trojan", "emerging-worm", "emerging-webserver",
    "emerging-web_specific_apps", "emerging-web_server", "emerging-web_client", "emerging-user_agents",
    "emerging-mobile_malware", "emerging-current_events", "emerging-dns", "emerging-ftp", "emerging-telnet",
    "emerging-rpc", "emerging-smtp", "emerging-snmp", "emerging-sql", "emerging-tftp", "emerging-voip",
    "emerging-netbios", "emerging-icmp_info", "emerging-imap", "emerging-pop3", "emerging-misc",
    "emerging-p2p", "emerging-policy", "emerging-adware_pup", "emerging-coinminer", "emerging-phishing",
    "emerging-hunting", "emerging-info", "emerging-ja3", "emerging-activex", "emerging-chat", "emerging-games",
    "emerging-inappropriate", "emerging-deleted", "emerging-scada", "emerging-dshield", "dshield", "ciarmy",
    "compromised", "drop", "tor",
]

STRIP_KEYS = {"id", "metadata", "index", "default", "management"}


def _clean(body: dict, keep_management: bool = True) -> dict:
    out = {k: v for k, v in body.items() if k not in STRIP_KEYS}
    if keep_management and "management" in body:
        out["management"] = body["management"]
    return out


def apply_fix(c: UniFiClient, action: str, params: dict) -> dict:
    """Aplica uma correcao guiada. Retorna {ok, message, result}."""
    if action == "set_ips_mode":
        cur = c.setting("ips")
        mode = params.get("mode", "ips")
        body = {**{k: v for k, v in cur.items() if not k.startswith("_") and k not in ("site_id",)}, "ips_mode": mode}
        if not body.get("enabled_categories"):
            body["enabled_categories"] = RECOMMENDED_IPS_CATEGORIES
        r = c.set_setting("ips", body)
        return {"ok": True, "message": f"IPS configurado no modo '{mode}'.", "result": r}
    if action == "set_ips_categories":
        cur = c.setting("ips")
        body = {**{k: v for k, v in cur.items() if not k.startswith("_") and k != "site_id"}, "enabled_categories": RECOMMENDED_IPS_CATEGORIES}
        if (body.get("ips_mode") or "disabled") == "disabled":
            body["ips_mode"] = "ips"
        r = c.set_setting("ips", body)
        return {"ok": True, "message": "Categorias recomendadas ativadas.", "result": r}
    if action == "set_ips_flag":
        cur = c.setting("ips")
        body = {**{k: v for k, v in cur.items() if not k.startswith("_") and k != "site_id"}, params["field"]: params["value"]}
        r = c.set_setting("ips", body)
        return {"ok": True, "message": f"'{params['field']}' definido como {params['value']}.", "result": r}
    if action == "set_usg_flag":
        cur = c.setting("usg")
        body = {**{k: v for k, v in cur.items() if not k.startswith("_") and k != "site_id"}, params["field"]: params["value"]}
        r = c.set_setting("usg", body)
        return {"ok": True, "message": f"'{params['field']}' definido como {params['value']}.", "result": r}
    if action == "isolate_network":
        n = c.network(params["networkId"])
        body = _clean(n)
        body["isolationEnabled"] = True
        r = c.update_network(n["id"], body)
        return {"ok": True, "message": f"Rede '{n.get('name')}' isolada.", "result": r}
    if action == "dhcp_guarding":
        n = c.network(params["networkId"])
        body = _clean(n)
        gw = ((n.get("ipv4Configuration") or {}).get("hostIpAddress"))
        if not gw:
            raise UniFiError("Rede sem IP de gateway; nao e possivel definir servidor DHCP confiavel.")
        body["dhcpGuarding"] = {"trustedDhcpServerIpAddresses": [gw]}
        r = c.update_network(n["id"], body)
        return {"ok": True, "message": f"DHCP Guarding ativado em '{n.get('name')}' (servidor confiavel {gw}).", "result": r}
    if action == "wifi_client_isolation":
        w = c.wifi_detail(params["wifiId"])
        body = _clean(w)
        body["clientIsolationEnabled"] = True
        r = c.update_wifi(w["id"], body)
        return {"ok": True, "message": f"Isolamento de clientes ativado em '{w.get('name')}'.", "result": r}
    if action == "wifi_enable_wpa3":
        w = c.wifi_detail(params["wifiId"])
        body = _clean(w)
        sec = body.get("securityConfiguration") or {}
        sec["type"] = "WPA2_WPA3_PERSONAL"
        if not sec.get("pmfMode"):
            sec["pmfMode"] = "OPTIONAL"
        body["securityConfiguration"] = sec
        r = c.update_wifi(w["id"], body)
        return {"ok": True, "message": f"Seguranca da WiFi '{w.get('name')}' atualizada para WPA2/WPA3 Misto.", "result": r}
    if action == "block_network_wan":
        n = c.network(params["networkId"])
        body = _clean(n)
        body["internetAccessEnabled"] = False
        r = c.update_network(n["id"], body)
        return {"ok": True, "message": f"Acesso a Internet de saida bloqueado para a rede '{n.get('name')}'.", "result": r}
    if action == "wifi_disable":
        w = c.wifi_detail(params["wifiId"])
        body = _clean(w)
        body["enabled"] = False
        r = c.update_wifi(w["id"], body)
        return {"ok": True, "message": f"WiFi '{w.get('name')}' desativada.", "result": r}
    if action == "policy_logging":
        r = c.patch_firewall_policy(params["policyId"], {"loggingEnabled": True})
        return {"ok": True, "message": "Log ativado na politica.", "result": r}
    if action in ("disable_policy", "enable_policy"):
        pol = c.api("GET", c.sp(f"/firewall/policies/{params['policyId']}"))
        body = _clean(pol)
        body["enabled"] = action == "enable_policy"
        r = c.api("PUT", c.sp(f"/firewall/policies/{pol['id']}"), json=body)
        return {"ok": True, "message": "Politica " + ("ativada." if body["enabled"] else "desativada."), "result": r}
    if action == "create_block_policy":
        body = build_block_policy(params)
        r = c.create_firewall_policy(body)
        return {"ok": True, "message": f"Politica '{body['name']}' criada.", "result": r}
    if action == "block_client":
        r = c.block_client(params["mac"], True)
        return {"ok": True, "message": f"Cliente {params['mac']} bloqueado.", "result": r}
    if action == "unblock_client":
        r = c.block_client(params["mac"], False)
        return {"ok": True, "message": f"Cliente {params['mac']} desbloqueado.", "result": r}
    if action == "restart_device":
        r = c.device_action(params["deviceId"], "RESTART")
        return {"ok": True, "message": "Reinicializacao solicitada.", "result": r}
    raise UniFiError(f"Acao desconhecida: {action}")


def build_block_policy(p: dict) -> dict:
    """Monta o corpo de uma politica de firewall (Integration API) a partir do assistente."""
    action = p.get("actionType", "BLOCK")
    body: dict[str, Any] = {
        "name": p.get("name") or "Bloqueio criado pelo painel",
        "description": p.get("description") or "Criado pelo Painel UniFi de Seguranca",
        "enabled": p.get("enabled", True),
        "loggingEnabled": p.get("loggingEnabled", True),
        "action": {"type": action},
        "source": {"zoneId": p["sourceZoneId"]},
        "destination": {"zoneId": p["destinationZoneId"]},
        "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"},
    }
    if p.get("connectionStates"):
        body["connectionStateFilter"] = p["connectionStates"]
    if p.get("sourceNetworkIds"):
        body["source"]["trafficFilter"] = {"type": "NETWORK", "networkFilter": {"matchOpposite": False, "networkIds": p["sourceNetworkIds"]}}
    if p.get("destinationNetworkIds"):
        body["destination"]["trafficFilter"] = {"type": "NETWORK", "networkFilter": {"matchOpposite": False, "networkIds": p["destinationNetworkIds"]}}
    elif p.get("destinationPorts"):
        body["destination"]["trafficFilter"] = {
            "type": "PORT",
            "portFilter": {"type": "PORTS", "matchOpposite": False,
                           "items": [_port(x) for x in p["destinationPorts"]]},
        }
    if p.get("protocol") in ("TCP", "UDP", "ICMP"):
        body["ipProtocolScope"]["protocolFilter"] = {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": p["protocol"]}}
    elif p.get("protocol") == "TCP_UDP":
        body["ipProtocolScope"]["protocolFilter"] = {"type": "PRESET", "preset": {"name": "TCP_UDP"}}
    return body


def _port(x) -> dict:
    s = str(x).strip()
    if "-" in s:
        a, b = s.split("-", 1)
        return {"type": "PORT_NUMBER_RANGE", "start": int(a), "stop": int(b)}
    return {"type": "PORT_NUMBER", "value": int(s)}
