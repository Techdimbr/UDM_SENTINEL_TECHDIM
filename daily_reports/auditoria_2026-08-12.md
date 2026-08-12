# Relatório de Auditoria Diária UDM Pro (Offline - Sem IA)

**Data:** 12/08/2026
**Aviso:** Ocorreu um erro ao consultar a inteligência artificial: Variável GEMINI_API_KEY ou API_KEY não configurada no ambiente.

### Resumo de Anomalias Críticas Detectadas:
- **Exfiltração de Dados (VLAN IoT):** Dispositivo `192.168.30.22` enviando tráfego anormal de 12.4 GB. Recomenda-se isolar a porta do Switch USW-24-PoE #18 imediatamente.
- **DNS Tunneling (VLAN Visitantes):** Dispositivo `192.168.20.101` realizando requisições maliciosas. Recomenda-se desativar o DNS direto para a WAN.
- **Wi-Fi Deauth Attack:** Ataque ativo contra AP `U6-Pro-Escritorio`. Recomenda-se habilitar PMF (Protected Management Frames) de forma Obrigatória.