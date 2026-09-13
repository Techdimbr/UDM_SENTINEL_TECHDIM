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

# Camada de aprofundamento: como a tecnica funciona, o que pode causar, em que etapa de
# um ataque aparece e o mapeamento MITRE ATT&CK. Indexada pelo titulo da categoria acima
# para nao duplicar o catalogo.
CATEGORY_DETAIL: dict[str, dict[str, Any]] = {
    "Malware / Trojan / Botnet (C&C)": {
        "how": "O malware ja instalado abre uma conexao de saida periodica (beacon) para o servidor do operador. Usa portas e protocolos comuns - HTTPS, DNS, HTTP - justamente para se misturar ao trafego legitimo e atravessar o firewall, que costuma liberar saida. O IDS reconhece o padrao do beacon: intervalo regular, tamanho de pacote caracteristico, certificado TLS ou User-Agent especifico da familia.",
        "canCause": "Roubo de credenciais e arquivos, instalacao de ransomware, uso da sua conexao para atacar terceiros (e a responsabilidade legal que vem junto) e persistencia: enquanto o canal existir, o invasor volta mesmo depois de limpar o sintoma.",
        "stage": "Comando e controle - o invasor ja esta dentro",
        "mitre": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
                  {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
                  {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
        "urgency": "Trate como incidente ativo: ha um host comprometido na rede agora.",
    },
    "Tentativa de exploracao de vulnerabilidade": {
        "how": "O atacante envia uma requisicao propositalmente malformada para um servico exposto, explorando uma falha conhecida (estouro de buffer, desserializacao insegura, injecao de template). A assinatura casa com o formato exato do payload publicado na CVE. A maior parte vem de bots que varrem a internet inteira testando a falha da semana.",
        "canCause": "Execucao remota de codigo no dispositivo alvo, o que normalmente vira acesso administrativo. A partir dai o invasor tem um ponto de apoio interno - e cameras, NAS e DVRs sao alvos preferidos porque quase nunca sao atualizados.",
        "stage": "Intrusao inicial",
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                  {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
        "urgency": "Se foi bloqueado e o servico nem esta exposto, e ruido. Se o alvo tem porta aberta na WAN, verifique o dispositivo hoje.",
    },
    "Varredura / Reconhecimento de rede": {
        "how": "Envio sistematico de pacotes para varias portas ou varios IPs, medindo o que responde. Um SYN scan manda so o primeiro pacote do handshake: porta aberta responde SYN/ACK, fechada responde RST, filtrada nao responde nada. O IDS detecta pela taxa - muitas tentativas distintas vindas da mesma origem em pouco tempo.",
        "canCause": "Sozinha nao causa dano: e levantamento. O risco e o que vem depois, porque o atacante agora sabe exatamente quais servicos e versoes existem para atacar. Vindo de um IP interno o significado inverte - indica host comprometido mapeando a rede por dentro.",
        "stage": "Reconhecimento - preparacao de ataque",
        "mitre": [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
                  {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}],
        "urgency": "Da internet: ruido constante, normal. De dentro da rede: investigue o host.",
    },
    "Negacao de servico (DoS/DDoS)": {
        "how": "Consome um recurso finito ate ele acabar: banda do link, tabela de conexoes do firewall, CPU do servidor. Um SYN flood abre milhares de conexoes pela metade e nunca completa o handshake, enchendo a tabela de estados. Amplificacao usa servicos UDP (DNS, NTP, memcached) que respondem muito mais do que recebem, com o IP de origem forjado para o da vitima.",
        "canCause": "Queda do link ou dos servicos enquanto durar. Se a origem for interna, seu IP publico entra em listas de reputacao e o provedor pode suspender o contrato - alem de indicar que ha um dispositivo seu recrutado em botnet.",
        "stage": "Impacto",
        "mitre": [{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
                  {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}],
        "urgency": "Origem interna e urgente. Ataque de fora sustentado exige acionar o provedor - filtrar no seu gateway nao devolve a banda ja consumida no caminho.",
    },
    "Violacao de politica / Uso de P2P, TOR ou proxies": {
        "how": "Trafego tecnicamente valido, mas de categorias que contornam controles. TOR encapsula em varias camadas de criptografia e salta por reles, escondendo o destino final. BitTorrent conecta a centenas de pares desconhecidos ao mesmo tempo. Proxies e VPNs de terceiros tiram a visibilidade do gateway sobre o que trafega.",
        "canCause": "Perda de visibilidade (voce deixa de enxergar o que sai da rede), download de arquivos de fontes nao verificadas e exposicao juridica por conteudo. TOR em rede corporativa costuma ser exfiltracao ou malware buscando canal de controle, nao curiosidade do usuario.",
        "stage": "Evasao de controles",
        "mitre": [{"id": "T1090.003", "name": "Proxy: Multi-hop Proxy", "tactic": "Command and Control"},
                  {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}],
        "urgency": "Avalie o contexto: pode ser uso legitimo. Em rede de empresa, TOR merece conversa com o dono do dispositivo.",
    },
    "Phishing / Roubo de credenciais": {
        "how": "A vitima recebe um link que imita um servico real - dominio parecido, certificado TLS valido, pagina clonada. Ao digitar a senha, ela vai para o atacante. Kits modernos fazem proxy reverso da sessao real e capturam tambem o cookie apos o segundo fator, o que derruba o 2FA por SMS ou codigo.",
        "canCause": "Comprometimento de contas de e-mail, banco e do proprio console UniFi. Conta de e-mail tomada vira ponto de partida para redefinir a senha de todo o resto e para atacar seus contatos usando sua identidade.",
        "stage": "Intrusao inicial / acesso a credenciais",
        "mitre": [{"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
                  {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"}],
        "urgency": "Se alguem digitou a senha, troque agora e encerre as sessoes ativas - so trocar a senha nao expulsa quem ja tem o cookie.",
    },
    "Mineracao de criptomoedas": {
        "how": "O minerador conecta a um pool usando o protocolo Stratum e recebe trabalho continuo, ocupando CPU ou GPU em 100%. Chega por malware, container comprometido ou script em pagina web. O IDS detecta pelo handshake do Stratum e pelos dominios conhecidos de pools.",
        "canCause": "Conta de energia alta, desgaste termico do equipamento e lentidao geral. E sobretudo: se um minerador conseguiu rodar, o caminho de entrada continua aberto para algo pior - quem vende acesso a minerador tambem vende a operador de ransomware.",
        "stage": "Impacto - sequestro de recursos",
        "mitre": [{"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact"}],
        "urgency": "Trate como sinal de comprometimento, nao so como incomodo de desempenho.",
    },
    "Consulta DNS suspeita / Informativo": {
        "how": "Antes de conectar, o malware resolve o nome do servidor de controle. Muitos usam DNS dinamico ou algoritmos que geram centenas de dominios por dia (DGA), de modo que derrubar um dominio nao mata o canal. Ha ainda o tunelamento: dados codificados dentro das proprias consultas DNS, que quase todo firewall libera.",
        "canCause": "A consulta em si e inofensiva - ela denuncia a intencao. Se resolveu, provavelmente houve conexao em seguida. Tunel DNS permite exfiltrar dados de forma lenta e discreta, driblando controles que so olham HTTP.",
        "stage": "Comando e controle - preparacao",
        "mitre": [{"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
                  {"id": "T1568", "name": "Dynamic Resolution", "tactic": "Command and Control"}],
        "urgency": "Verifique o dominio consultado antes de concluir.",
        "falsePositive": "Muitos falsos positivos aqui sao servicos legitimos de DNS dinamico.",
    },
    "Adware / Spyware / Software indesejado": {
        "how": "Programas instalados junto com outro software ('bundling') ou extensoes de navegador com permissao ampla de leitura de paginas. Coletam historico, formularios e as vezes teclas digitadas, enviando para servidores de publicidade ou corretores de dados.",
        "canCause": "Vazamento de habitos, dados de formulario e eventualmente credenciais. Injecao de anuncios em paginas legitimas, que vira vetor para malware mais serio. Degradacao de desempenho do dispositivo.",
        "stage": "Coleta de dados",
        "mitre": [{"id": "T1176", "name": "Browser Extensions", "tactic": "Persistence"},
                  {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"}],
        "urgency": "Baixa urgencia imediata, mas limpe: e sintoma de que algo instala software sem consentimento nesse dispositivo.",
    },
    "Ameaca em dispositivo movel": {
        "how": "Aplicativo malicioso instalado fora da loja oficial, ou app legitimo com SDK de propaganda agressivo. Pede permissoes amplas (SMS, acessibilidade, sobreposicao de tela) e as usa para ler codigos de autenticacao ou sobrepor telas falsas de banco.",
        "canCause": "Fraude bancaria com interceptacao do segundo fator por SMS, roubo de contatos e mensagens, e o celular virando ponto de entrada na rede WiFi de casa ou da empresa.",
        "stage": "Intrusao inicial em endpoint movel",
        "mitre": [{"id": "T1461", "name": "Lockscreen Bypass", "tactic": "Initial Access (Mobile)"},
                  {"id": "T1417", "name": "Input Capture", "tactic": "Credential Access (Mobile)"}],
        "urgency": "Revise apps instalados recentemente e permissoes de acessibilidade.",
    },
    "Protocolos industriais / IoT / VoIP": {
        "how": "Protocolos como Modbus, BACnet e SIP foram desenhados sem autenticacao, assumindo rede confiavel. Quem alcanca a porta consegue ler e escrever comandos. Em VoIP o alvo tipico e o registro SIP: o atacante tenta ramais com senha fraca para originar chamadas as suas custas.",
        "canCause": "Em IoT/OT, controle fisico indevido de equipamentos. Em VoIP, fraude tarifaria com chamadas internacionais. E dispositivos IoT comprometidos sao a porta de entrada classica para movimento lateral, porque ninguem monitora a camera.",
        "stage": "Movimento lateral / acesso a OT",
        "mitre": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"},
                  {"id": "T0886", "name": "Remote Services (ICS)", "tactic": "Lateral Movement (ICS)"}],
        "urgency": "Segmentar em VLAN isolada resolve a maior parte disso de uma vez.",
    },
    "Comunicacao com IP de ma reputacao": {
        "how": "Nao ha analise de conteudo: a assinatura casa apenas o endereco IP contra listas publicas (Spamhaus DROP, DShield, CINS, nos de saida TOR). Sao listas de infraestrutura ja observada em atividade maliciosa por outros pesquisadores.",
        "canCause": "Depende inteiramente da direcao. De fora para dentro e bloqueado: funcionamento normal, ruido de fundo da internet. De dentro para fora e o sinal importante - um dispositivo seu escolheu falar com infraestrutura marcada como maliciosa.",
        "stage": "Varia conforme a direcao",
        "mitre": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
        "urgency": "Saida iniciada de dentro merece investigacao. Entrada bloqueada nao exige acao.",
        "falsePositive": "Alta chance de falso positivo: faixas de nuvem compartilhada (AWS, Azure, OVH) entram nas listas por causa de um vizinho e acabam marcando servicos legitimos.",
    },
    "Forca bruta / Acesso a servicos administrativos": {
        "how": "Tentativas automatizadas de autenticacao contra SSH, RDP, SMB, FTP ou Telnet, usando listas de senhas vazadas em incidentes anteriores. A variante mais dificil de detectar e o 'password spraying': poucas tentativas por conta, mas contra muitas contas, para nao disparar bloqueio por tentativas.",
        "canCause": "Acesso administrativo direto ao dispositivo. RDP exposto e hoje um dos principais vetores iniciais de ransomware: o invasor entra com credencial valida, entao nenhum antivirus reclama, e a partir dai cifra o que alcanca.",
        "stage": "Acesso a credenciais",
        "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                  {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
                  {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"}],
        "urgency": "Se o servico esta exposto na internet, tire da WAN hoje e coloque atras de VPN. Nao ha senha forte o bastante para compensar exposicao permanente.",
    },
    "Assinatura de seguranca generica": {
        "how": "O pacote casou com uma regra do conjunto Emerging Threats que nao se encaixa nas categorias mapeadas acima. Regras variam muito em precisao: algumas identificam uma familia especifica de malware, outras apenas sinalizam um padrao incomum que merece atencao.",
        "canCause": "Indeterminado sem analise do caso. Vale olhar a assinatura exata e a direcao do trafego antes de concluir qualquer coisa.",
        "stage": "Indeterminado",
        "mitre": [],
        "urgency": "Pesquise o nome exato da assinatura. Se repete sempre com o mesmo dispositivo interno, investigue esse dispositivo.",
        "falsePositive": "Sem contexto adicional, assuma que pode ser falso positivo ate confirmar.",
    },
}

# Grupos de regras do Emerging Threats, para explicar de onde a deteccao veio.
ET_CATEGORY_INFO: dict[str, str] = {
    "emerging-malware": "Malware conhecido: beacons, downloaders e trafego de familias catalogadas.",
    "emerging-trojan": "Trojans e backdoors - foco em canal de controle e exfiltracao.",
    "emerging-botcc": "Servidores de comando e controle de botnets, alimentado por inteligencia de ameacas.",
    "botcc": "Comando e controle de botnets (Shadowserver e fontes equivalentes).",
    "emerging-exploit": "Exploracao de vulnerabilidades especificas, geralmente com CVE associada.",
    "emerging-scan": "Ferramentas de varredura e reconhecimento (nmap, masscan, scanners de aplicacao).",
    "emerging-dos": "Padroes de negacao de servico e amplificacao.",
    "emerging-policy": "Trafego que viola politica corporativa tipica, sem ser malicioso por si.",
    "emerging-phishing": "Paginas e campanhas de roubo de credenciais.",
    "emerging-coinminer": "Mineracao de criptomoedas, pools e protocolo Stratum.",
    "emerging-user_agents": "User-Agents associados a ferramentas maliciosas ou software indesejado.",
    "emerging-attackresponse": "Respostas que indicam ataque bem-sucedido (ex.: saida de comando shell).",
    "emerging-shellcode": "Shellcode e padroes de execucao de codigo em memoria.",
    "emerging-webserver": "Ataques contra servidores web.",
    "emerging-web_specific_apps": "Falhas em aplicacoes web especificas (CMS, plugins, paineis).",
    "emerging-dshield": "IPs reportados ao DShield/SANS como atacantes ativos.",
    "dshield": "Lista de atacantes do DShield/SANS.",
    "ciarmy": "Lista CINS Army de IPs com reputacao ruim.",
    "compromised": "Hosts legitimos ja comprometidos e usados em ataques.",
    "drop": "Spamhaus DROP: faixas sequestradas ou controladas por criminosos.",
    "tor": "Nos de entrada e saida da rede TOR.",
    "emerging-mobile_malware": "Malware para Android e iOS.",
    "emerging-current_events": "Campanhas ativas no momento - regras de vida curta, alta relevancia.",
    "emerging-hunting": "Regras de cacada: geram muito ruido de proposito, para investigacao.",
    "emerging-info": "Informativas: registram comportamento notavel sem afirmar que e ataque.",
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

    detail = CATEGORY_DETAIL.get(info["title"], {})
    et_group = (catname or "").lower().strip()
    sid = ev.get("inner_alert_signature_id") or ev.get("signature_id")

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
        # aprofundamento tecnico
        "how": detail.get("how"),
        "canCause": detail.get("canCause"),
        "stage": detail.get("stage"),
        "mitre": detail.get("mitre", []),
        "urgency": detail.get("urgency"),
        "falsePositive": detail.get("falsePositive"),
        "etGroup": et_group or None,
        "etGroupInfo": ET_CATEGORY_INFO.get(et_group),
        "sidUrl": f"https://www.google.com/search?q=%22{sid}%22+suricata+signature" if sid else None,
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
