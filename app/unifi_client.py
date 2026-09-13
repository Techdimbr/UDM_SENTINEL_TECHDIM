"""Cliente HTTP para o UniFi Network (UDM Pro).

Suporta dois modos de conexao:
  * local  -> https://<ip-do-udm>/proxy/network/integration/v1/...  (chave API local, gerada no console)
  * cloud  -> https://api.ui.com/v1/connector/consoles/<consoleId>/...  (chave API do Site Manager, unifi.ui.com)

Alem da Integration API (oficial, OpenAPI), usa a API "classica" do controlador
(/proxy/network/api/s/<site>/...) para dados que a Integration API ainda nao expoe:
eventos, alarmes, ameacas do IPS/IDS, health e configuracoes de seguranca.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx


class UniFiError(Exception):
    def __init__(self, message: str, status: int | None = None, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


@dataclass
class UniFiConfig:
    mode: str = "local"               # "local" | "cloud"
    host: str = ""                    # ip/hostname do UDM (modo local)
    console_id: str = ""              # id do console (modo cloud)
    api_key: str = ""
    site_id: str = ""                 # uuid do site (Integration API); vazio = primeiro site
    verify_ssl: bool = False
    timeout: float = 20.0

    def is_configured(self) -> bool:
        if not self.api_key:
            return False
        return bool(self.host) if self.mode == "local" else bool(self.console_id)


@dataclass
class _Cache:
    data: dict[str, tuple[float, Any]] = field(default_factory=dict)

    def get(self, key: str, ttl: float):
        item = self.data.get(key)
        if item and time.time() - item[0] < ttl:
            return item[1]
        return None

    def set(self, key: str, value: Any):
        self.data[key] = (time.time(), value)


class UniFiClient:
    def __init__(self, cfg: UniFiConfig):
        self.cfg = cfg
        self._cache = _Cache()
        self._integration_base: str | None = None
        self._classic_base: str | None = None
        self._classic_available: bool | None = None
        self._site: dict | None = None
        self._client = httpx.Client(
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
            headers={"X-API-KEY": cfg.api_key, "Accept": "application/json"},
        )

    # ------------------------------------------------------------------ bases
    def _integration_candidates(self) -> list[str]:
        if self.cfg.mode == "cloud":
            root = f"https://api.ui.com/v1/connector/consoles/{self.cfg.console_id}"
            return [f"{root}/proxy/network/integration", f"{root}/network/integration"]
        host = self.cfg.host.strip().rstrip("/")
        if not host.startswith("http"):
            host = "https://" + host
        return [f"{host}/proxy/network/integration"]

    def _classic_candidates(self) -> list[str]:
        if self.cfg.mode == "cloud":
            root = f"https://api.ui.com/v1/connector/consoles/{self.cfg.console_id}"
            return [f"{root}/proxy/network/api", f"{root}/network/api"]
        host = self.cfg.host.strip().rstrip("/")
        if not host.startswith("http"):
            host = "https://" + host
        return [f"{host}/proxy/network/api"]

    def _request(self, method: str, url: str, **kw) -> Any:
        try:
            r = self._client.request(method, url, **kw)
        except httpx.ConnectError as e:
            raise UniFiError(f"Nao foi possivel conectar em {url}: {e}") from e
        except httpx.TimeoutException as e:
            raise UniFiError(f"Tempo esgotado ao acessar {url}") from e
        if r.status_code >= 400:
            detail: Any
            try:
                detail = r.json()
            except ValueError:
                detail = r.text[:500]
            msg = {
                401: "Chave API invalida ou sem permissao (401).",
                403: "Acesso negado (403) - verifique as permissoes da chave API.",
                404: "Recurso nao encontrado (404).",
                429: "Limite de requisicoes atingido (429) - aguarde alguns segundos.",
            }.get(r.status_code, f"Erro HTTP {r.status_code}")
            raise UniFiError(msg, status=r.status_code, detail=detail)
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    def integration_base(self) -> str:
        if self._integration_base:
            return self._integration_base
        last: Exception | None = None
        for base in self._integration_candidates():
            try:
                self._request("GET", f"{base}/v1/info")
                self._integration_base = base
                return base
            except UniFiError as e:
                last = e
                if e.status in (401, 403):
                    raise
        raise last or UniFiError("Nenhuma base da Integration API respondeu")

    # ------------------------------------------------------------ integration
    def api(self, method: str, path: str, params: dict | None = None, json: Any = None) -> Any:
        base = self.integration_base()
        return self._request(method, f"{base}{path}", params=params, json=json)

    def paged(self, path: str, params: dict | None = None, limit: int = 200, max_items: int = 5000) -> list[dict]:
        """Percorre todas as paginas de um endpoint paginado da Integration API."""
        out: list[dict] = []
        offset = 0
        params = dict(params or {})
        while True:
            params.update({"offset": offset, "limit": limit})
            page = self.api("GET", path, params=params)
            if isinstance(page, list):
                return page
            data = page.get("data", []) if isinstance(page, dict) else []
            out.extend(data)
            total = page.get("totalCount", len(out)) if isinstance(page, dict) else len(out)
            offset += len(data)
            if not data or offset >= total or offset >= max_items:
                break
        return out

    def info(self) -> dict:
        cached = self._cache.get("info", 60)
        if cached:
            return cached
        v = self.api("GET", "/v1/info")
        self._cache.set("info", v)
        return v

    def sites(self) -> list[dict]:
        cached = self._cache.get("sites", 300)
        if cached:
            return cached
        v = self.paged("/v1/sites")
        self._cache.set("sites", v)
        return v

    def site(self) -> dict:
        if self._site:
            return self._site
        sites = self.sites()
        if not sites:
            raise UniFiError("Nenhum site encontrado no controlador")
        chosen = sites[0]
        if self.cfg.site_id:
            for s in sites:
                if s.get("id") == self.cfg.site_id or s.get("internalReference") == self.cfg.site_id:
                    chosen = s
                    break
        self._site = chosen
        return chosen

    def sp(self, suffix: str) -> str:
        return f"/v1/sites/{self.site()['id']}{suffix}"

    def devices(self) -> list[dict]:
        return self.paged(self.sp("/devices"))

    def device(self, device_id: str) -> dict:
        return self.api("GET", self.sp(f"/devices/{device_id}"))

    def device_stats(self, device_id: str) -> dict:
        return self.api("GET", self.sp(f"/devices/{device_id}/statistics/latest"))

    def pending_devices(self) -> list[dict]:
        return self.paged("/v1/pending-devices")

    def clients(self) -> list[dict]:
        return self.paged(self.sp("/clients"))

    def client(self, client_id: str) -> dict:
        return self.api("GET", self.sp(f"/clients/{client_id}"))

    def networks(self) -> list[dict]:
        return self.paged(self.sp("/networks"))

    def network(self, network_id: str) -> dict:
        return self.api("GET", self.sp(f"/networks/{network_id}"))

    def wifi(self) -> list[dict]:
        return self.paged(self.sp("/wifi/broadcasts"))

    def wifi_detail(self, wifi_id: str) -> dict:
        return self.api("GET", self.sp(f"/wifi/broadcasts/{wifi_id}"))

    def firewall_zones(self) -> list[dict]:
        return self.paged(self.sp("/firewall/zones"))

    def firewall_policies(self) -> list[dict]:
        return self.paged(self.sp("/firewall/policies"))

    def create_firewall_policy(self, body: dict) -> dict:
        return self.api("POST", self.sp("/firewall/policies"), json=body)

    def patch_firewall_policy(self, policy_id: str, body: dict) -> dict:
        return self.api("PATCH", self.sp(f"/firewall/policies/{policy_id}"), json=body)

    def update_network(self, network_id: str, body: dict) -> dict:
        return self.api("PUT", self.sp(f"/networks/{network_id}"), json=body)

    def update_wifi(self, wifi_id: str, body: dict) -> dict:
        return self.api("PUT", self.sp(f"/wifi/broadcasts/{wifi_id}"), json=body)

    def acl_rules(self) -> list[dict]:
        return self.paged(self.sp("/acl-rules"))

    def firewall_ordering(self) -> Any:
        """Ordem atual das politicas definidas pelo usuario (a primeira que casar decide)."""
        return self.api("GET", self.sp("/firewall/policies/ordering"))

    def set_firewall_ordering(self, policy_ids: list[str]) -> Any:
        return self.api("PUT", self.sp("/firewall/policies/ordering"), json={"firewallPolicyIds": policy_ids})

    def create_dns_policy(self, body: dict) -> dict:
        return self.api("POST", self.sp("/dns/policies"), json=body)

    def delete_dns_policy(self, policy_id: str) -> Any:
        return self.api("DELETE", self.sp(f"/dns/policies/{policy_id}"))

    def dns_policies(self) -> list[dict]:
        return self.paged(self.sp("/dns/policies"))

    def vpn_servers(self) -> list[dict]:
        return self.paged(self.sp("/vpn/servers"))

    def vpn_tunnels(self) -> list[dict]:
        return self.paged(self.sp("/vpn/site-to-site-tunnels"))

    def wans(self) -> list[dict]:
        return self.paged(self.sp("/wans"))

    def traffic_lists(self) -> list[dict]:
        return self.paged(self.sp("/traffic-matching-lists"))

    def dpi_categories(self) -> list[dict]:
        cached = self._cache.get("dpi_cat", 3600)
        if cached:
            return cached
        v = self.paged("/v1/dpi/categories")
        self._cache.set("dpi_cat", v)
        return v

    def vouchers(self) -> list[dict]:
        return self.paged(self.sp("/hotspot/vouchers"))

    def device_action(self, device_id: str, action: str) -> Any:
        return self.api("POST", self.sp(f"/devices/{device_id}/actions"), json={"action": action})

    # ----------------------------------------------------------------- classic
    def classic_site_name(self) -> str:
        return self.site().get("internalReference") or "default"

    def classic(self, method: str, path: str, params: dict | None = None, json: Any = None) -> Any:
        """Chama a API classica (/proxy/network/api/s/<site>/...).

        `path` comeca apos "/s/<site>", por ex. "/stat/ips/event".
        Lanca UniFiError se a API classica nao estiver acessivel com a chave API.
        """
        if self._classic_available is False:
            raise UniFiError("API classica indisponivel nesta conexao", status=None)
        site = self.classic_site_name()
        bases = [self._classic_base] if self._classic_base else self._classic_candidates()
        last: Exception | None = None
        for base in bases:
            try:
                data = self._request(method, f"{base}/s/{site}{path}", params=params, json=json)
                self._classic_base = base
                self._classic_available = True
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                return data
            except UniFiError as e:
                last = e
                if e.status in (401, 403, 404) and not self._classic_base:
                    continue
                raise
        self._classic_available = False
        raise last or UniFiError("API classica indisponivel")

    def classic_available(self) -> bool:
        if self._classic_available is None:
            try:
                self.classic("GET", "/stat/health")
            except UniFiError:
                self._classic_available = False
        return bool(self._classic_available)

    def health(self) -> list[dict]:
        return self.classic("GET", "/stat/health") or []

    def sysinfo(self) -> dict:
        d = self.classic("GET", "/stat/sysinfo")
        return d[0] if isinstance(d, list) and d else (d or {})

    def events(self, limit: int = 300, within_hours: int = 72) -> list[dict]:
        return self.classic("POST", "/stat/event", json={"_limit": limit, "within": within_hours, "_sort": "-time"}) or []

    def alarms(self, limit: int = 300) -> list[dict]:
        return self.classic("GET", "/stat/alarm", params={"_limit": limit}) or []

    def ips_events(self, limit: int = 500, start_ms: int | None = None, end_ms: int | None = None) -> list[dict]:
        now = int(time.time() * 1000)
        body = {
            "start": start_ms or now - 7 * 24 * 3600 * 1000,
            "end": end_ms or now,
            "_limit": limit,
            "_sort": "-time",
        }
        return self.classic("POST", "/stat/ips/event", json=body) or []

    def settings(self) -> list[dict]:
        return self.classic("GET", "/rest/setting") or []

    def setting(self, key: str) -> dict:
        for s in self.settings():
            if s.get("key") == key:
                return s
        return {}

    def classic_devices(self) -> list[dict]:
        return self.classic("GET", "/stat/device") or []

    def classic_clients(self) -> list[dict]:
        return self.classic("GET", "/stat/sta") or []

    def set_setting(self, key: str, body: dict) -> Any:
        return self.classic("PUT", f"/set/setting/{key}", json=body)

    def networkconf(self) -> list[dict]:
        """Configuracao bruta de redes da API classica.

        A Integration API expoe /vpn/servers somente para leitura; na API classica os
        servidores VPN aparecem aqui (purpose='vpn-server') e podem ser reescritos,
        que e o unico caminho para reamarrar a escuta da VPN a outra WAN.
        """
        return self.classic("GET", "/rest/networkconf") or []

    def update_networkconf(self, conf_id: str, body: dict) -> Any:
        return self.classic("PUT", f"/rest/networkconf/{conf_id}", json=body)

    def block_client(self, mac: str, block: bool = True) -> Any:
        cmd = "block-sta" if block else "unblock-sta"
        return self.classic("POST", "/cmd/stamgr", json={"cmd": cmd, "mac": mac.lower()})

    # ---------------------------------------------------------------- helpers
    def test_connection(self) -> dict:
        info = self.info()
        site = self.site()
        result = {
            "ok": True,
            "applicationVersion": info.get("applicationVersion"),
            "site": site,
            "integrationBase": self._integration_base,
            "classicApi": self.classic_available(),
            "classicBase": self._classic_base,
        }
        return result
