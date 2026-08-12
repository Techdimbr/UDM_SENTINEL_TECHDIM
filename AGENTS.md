# Guia de Execução de Agente Autónomo (Automação de Auditoria Diária)

O **UDM Pro Sentinel** possui um script nativo estruturado para ser chamado por agentes autónomos de monitoramento ou por agendadores de tarefas (como Cron Linux, GitHub Actions, ou tarefas programadas do Windows).

## Como Executar a Auditoria Diária Manualmente
Para rodar a auditoria diária imediatamente de forma manual:
```bash
bun run cron:daily
```
ou usando NPM:
```bash
npm run cron:daily
```

## Como Funciona o Script `dailyAudit.ts`
1. **Coleta de Telemetria:** O script tenta se conectar ao UDM Pro local ou público usando as variáveis de ambiente `UDM_HOST` e `UDM_API_KEY`. Se o console estiver inacessível (por exemplo, rodando offline ou em redes privadas), o script automaticamente utiliza telemetria de alta fidelidade simulada para não interromper a auditoria.
2. **Análise de IA de Anomalias de Tráfego:** Compila os dados de exfiltração de dados (IoT VLAN), desvios e túneis de DNS (Guest VLAN) e ataques de intrusão Wi-Fi (Deauth) e submete as informações estruturadas à API do Gemini.
3. **Persistência de Relatório Markdown:** Gera um relatório de conformidade diário estruturado, contendo a pontuação de risco da rede, e o salva chronologicamente na pasta `/daily_reports/auditoria_YYYY-MM-DD.md`.

## Configurações e Variáveis de Ambiente Necessárias
Para a execução perfeita do agente, configure as seguintes variáveis no seu ambiente ou arquivo `.env`:
* `GEMINI_API_KEY`: Chave de API da Google GenAI para habilitar as recomendações Blue Team baseadas em IA (Obrigatório para geração de relatório IA).
* `UDM_HOST`: Endereço IP ou hostname do UDM Pro (ex: `https://192.168.1.1`).
* `UDM_API_KEY`: Chave de autenticação API gerada no UniFi OS.

## Exemplo de Agendamento de Tarefas (Cron Linux)
Para rodar todos os dias à meia-noite (00:00), adicione a seguinte linha ao seu `crontab -e`:
```cron
0 0 * * * cd /caminho/do/seu/projeto && GEMINI_API_KEY="SUA_CHAVE" bun run cron:daily >> /var/log/udm_audit.log 2>&1
```

## Exemplo de Workflow Integrado no GitHub Actions
Caso o UDM Pro possua um IP WAN público ou VPN aberta, você pode rodar a auditoria em CI/CD usando o seguinte workflow `.github/workflows/daily_audit.yml`:
```yaml
name: UDM Pro Daily Security Audit

on:
  schedule:
    - cron: '0 0 * * *' # Roda todos os dias à meia-noite
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1

      - name: Install dependencies
        run: bun install

      - name: Run Daily Audit Agent
        run: bun run cron:daily
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          UDM_HOST: ${{ secrets.UDM_HOST }}
          UDM_API_KEY: ${{ secrets.UDM_API_KEY }}
```
