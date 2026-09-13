# Painel UniFi de Segurança (UDM Pro)

Painel web que se conecta ao seu UDM Pro por **chave API**, lê e interpreta todos os dados da rede e
guia a configuração de segurança.

- **Visão geral**: saúde do gateway, dispositivos, clientes, WAN, ameaças recentes, alarmes.
- **Ameaças (IDS/IPS)**: cada evento do Suricata explicado em português: o que é, de onde veio,
  se foi bloqueado, qual dispositivo interno está envolvido, CVE (quando houver) e o que fazer.
- **Auditoria guiada**: pontuação 0–100, achados por severidade com *por que importa*, *como
  corrigir no app UniFi* e botão **Aplicar** (via API, sempre com confirmação).
- **Firewall & Zonas**: zonas, políticas (traduzidas), assistente para criar políticas de bloqueio,
  ativar/desativar/log/excluir.
- **Redes & WiFi**, **Clientes** (bloquear/desbloquear), **Dispositivos** (portas, rádios, reiniciar),
  **Logs & Alarmes** (eventos traduzidos e classificados), **VPN/WAN/DNS**, **Explorador da API**.

## Requisitos

- Python 3.10+
- UDM Pro com UniFi Network 9.x+ (Integration API) — testado contra o OpenAPI Network API v10.3.58.

## Executar

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Abra `http://localhost:8000`, vá em **Configurações**, escolha o modo e cole a chave API.

### Obter a chave API

- **Local (recomendado)**: no UniFi Network do UDM Pro → *Settings → Control Plane → Integrations →
  Create API Key*. Informe o IP local do UDM (ex.: `192.168.1.1`). Este modo habilita também a API
  clássica (eventos, alarmes, IPS, configurações de IPS/UPnP).
- **Nuvem**: em [unifi.ui.com](https://unifi.ui.com) → *Settings → API → Create API Key* e informe
  o ID do console (da URL `unifi.ui.com/consoles/<ID>/...`).

A chave fica somente no servidor, em `~/.unifi-panel/config.json` (permissão 600), mascarada em
todas as respostas da API. Alternativamente use variáveis de ambiente:

```bash
UNIFI_MODE=local UNIFI_HOST=192.168.1.1 UNIFI_API_KEY=... uvicorn app.main:app
```

## Testes (sem UDM real)

```bash
pip install pytest ruff
pytest            # sobe um mock do UDM Pro e testa todas as rotas e ações
ruff check app tests
```

Para navegar no painel com dados fictícios:

```bash
python -m tests.mock_udm &                                     # UDM falso em :8443
UNIFI_HOST=http://127.0.0.1:8443 UNIFI_API_KEY=test-key-1234567890 \
UNIFI_PANEL_CONFIG=/tmp/panel.json uvicorn app.main:app
```

## Estrutura

| Arquivo | Função |
|---|---|
| `app/unifi_client.py` | Cliente HTTP: Integration API (local e Cloud Connector) + API clássica |
| `app/threats.py` | Base de conhecimento de ameaças e tradução de eventos/alarmes |
| `app/audit.py` | Auditoria de segurança, recomendações e ações corretivas |
| `app/main.py` | API REST (FastAPI) consumida pelo frontend |
| `static/` | Frontend (HTML/CSS/JS puro, Chart.js via CDN) |
| `docs/integration-endpoints.json` | 73 endpoints extraídos do OpenAPI oficial |
| `tests/mock_udm.py` | Servidor mock do UDM Pro |

## Referências

- [UniFi Network API (Integration)](https://developer.ui.com/network/v10.4.57/gettingstarted)
- [UniFi Site Manager API](https://developer.ui.com/site-manager/v1.0.0/gettingstarted)
