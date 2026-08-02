import React, { useState } from 'react';
import { ApiCapability } from '../types';
import { 
  ShieldCheck, Zap, Lock, Eye, Layers, Search, Filter, Cpu, 
  ExternalLink, CheckCircle2, Server, Terminal, Bot, ChevronRight
} from 'lucide-react';

const CAPABILITIES_DATA: ApiCapability[] = [
  // 1-10: Automação & Orquestração
  {
    id: 1,
    category: 'Automação & Orquestração',
    title: 'Bloqueio Automático em Tempo Real por Reputação de IP',
    description: 'Bloqueio ou desconexão imediata de endereços MAC/IP reportados por SIEMs externos, listas de reputação (AbuseIPDB, AlienVault) ou picos de tráfego malicioso.',
    apiEndpoint: '/proxy/network/api/s/default/cmd/stamgr',
    impact: 'CRÍTICO',
    valueProp: 'Neutraliza ataques ativos antes que propaguem lateralmente na rede interna.'
  },
  {
    id: 2,
    category: 'Automação & Orquestração',
    title: 'Quarentena Dinâmica de Clientes Suspeitos (VLAN Isolation)',
    description: 'Movimentação automática de dispositivos com comportamento anômalo para uma VLAN isolada sem acesso à rede corporativa.',
    apiEndpoint: '/proxy/network/v2/api/site/default/user/{id}',
    impact: 'CRÍTICO',
    valueProp: 'Contém malware e ransomware sem desligar totalmente o equipamento afetado.'
  },
  {
    id: 3,
    category: 'Automação & Orquestração',
    title: 'Agendamento Inteligente de SSIDs (Zero-Trust Off-Hours)',
    description: 'Desativação programada ou condicional de SSIDs corporativos ou de convidados fora do expediente ou em feriados.',
    apiEndpoint: '/proxy/network/api/s/default/rest/wlanconf',
    impact: 'ALTO',
    valueProp: 'Elimina o vetor de ataque físico e invasões Wi-Fi noturnas no perímetro empresarial.'
  },
  {
    id: 4,
    category: 'Automação & Orquestração',
    title: 'Revogação Instantânea de Acesso Wi-Fi de Ex-Funcionários',
    description: 'Integrador automático entre sistemas de RH/Active Directory e o UniFi OS para revogação imediata de credenciais WPA2/WPA3 Enterprise.',
    apiEndpoint: '/proxy/network/api/s/default/cmd/stamgr',
    impact: 'ALTO',
    valueProp: 'Garante política de offboarding sem atrito nem esquecimentos de senhas gravadas.'
  },
  {
    id: 5,
    category: 'Automação & Orquestração',
    title: 'Automação de Failover Multi-WAN com Notificação Push',
    description: 'Monitoramento contínuo de jitter e perda de pacotes da WAN1/WAN2 com execução de ações customizadas e avisos no Slack/Telegram.',
    apiEndpoint: '/proxy/network/api/s/default/stat/health',
    impact: 'ALTO',
    valueProp: 'Visibilidade proativa da estabilidade do link de internet principal e reserva.'
  },
  {
    id: 6,
    category: 'Automação & Orquestração',
    title: 'Políticas Dinâmicas de Bandwidth Throttle por Categoria',
    description: 'Limitação automática de banda para streaming ou jogos nos horários de maior uso das aplicações de negócio.',
    apiEndpoint: '/proxy/network/api/s/default/rest/usergroup',
    impact: 'MÉDIO',
    valueProp: 'Preserva a qualidade de serviço (QoS) do link de dados para VoIP e ERPs.'
  },
  {
    id: 7,
    category: 'Automação & Orquestração',
    title: 'Rotação Automática de Chaves PSK para Visitantes',
    description: 'Geração periódica automatizada (diária/semanal) da senha do Wi-Fi Guest com atualização dinâmica de QR Code na recepção.',
    apiEndpoint: '/proxy/network/api/s/default/rest/wlanconf',
    impact: 'MÉDIO',
    valueProp: 'Evita a reutilização indefinida da senha da rede de visitantes por ex-visitantes.'
  },
  {
    id: 8,
    category: 'Automação & Orquestração',
    title: 'Mitigação Automática de Port Scanning (Auto-Blacklist)',
    description: 'Criação instantânea de regras de firewall do tipo DROP para IPs externos que varrerem portas fechadas do gateway.',
    apiEndpoint: '/proxy/network/api/s/default/rest/firewallrule',
    impact: 'CRÍTICO',
    valueProp: 'Impede o reconhecimento proativo de atacantes contra a interface pública WAN.'
  },
  {
    id: 9,
    category: 'Automação & Orquestração',
    title: 'Desativação Temporária de Portas PoE Vulneráveis',
    description: 'Desligamento automático de portas de switches instaladas em locais físicos desprotegidos (ex: salas sem uso após horário comercial).',
    apiEndpoint: '/proxy/network/v2/api/site/default/device/{id}',
    impact: 'ALTO',
    valueProp: 'Proteção contra intrusão física por conexão de cabos Ethernet não autorizados.'
  },
  {
    id: 10,
    category: 'Automação & Orquestração',
    title: 'Reset de Conexões de IoTs com Comportamento Anormal',
    description: 'Forçar o re-handshake Wi-Fi ou reiniciar a porta PoE de dispositivos IoT que travarem ou apresentarem consumo anômalo.',
    apiEndpoint: '/proxy/network/api/s/default/cmd/devmgr',
    impact: 'MÉDIO',
    valueProp: 'Manutenção proativa e autocura da infraestrutura de IoT sem intervenção humana.'
  },

  // 11-20: Auditoria & Compliance
  {
    id: 11,
    category: 'Auditoria & Compliance',
    title: 'Auditoria de Drift de Regras de Firewall (Baseline vs Real)',
    description: 'Comparação contínua do estado atual do firewall com um modelo aprovado de segurança, alertando sobre regras alteradas.',
    apiEndpoint: '/proxy/network/api/s/default/rest/firewallrule',
    impact: 'CRÍTICO',
    valueProp: 'Detecta alterações não autorizadas ou erros humanos na política de segurança.'
  },
  {
    id: 12,
    category: 'Auditoria & Compliance',
    title: 'Detecção e Mapeamento de Dispositivos Não Homologados (Rogue)',
    description: 'Alertas em tempo real sobre a conexão de dispositivos com fabricantes desconhecidos ou MACs suspeitos.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'ALTO',
    valueProp: 'Garante o controle total sobre quais equipamentos ingressam no ambiente de rede.'
  },
  {
    id: 13,
    category: 'Auditoria & Compliance',
    title: 'Verificação da Saúde do Criptoprocessador e Certificados SSL',
    description: 'Monitoramento da validade de certificados digitais do UniFi OS e verificação do status de criptografia dos canais de gestão.',
    apiEndpoint: '/unifi-api/network',
    impact: 'MÉDIO',
    valueProp: 'Evita alertas de segurança no navegador e interrupções em portais cativos.'
  },
  {
    id: 14,
    category: 'Auditoria & Compliance',
    title: 'Geração de Relatórios Automáticos de Compliance (ISO 27001 / LGPD)',
    description: 'Exportação periódica de relatórios técnicos comprovando o isolamento de dados de clientes, políticas de acesso e logs.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sysinfo',
    impact: 'ALTO',
    valueProp: 'Facilita auditorias externas e demonstra conformidade regulatória para clientes.'
  },
  {
    id: 15,
    category: 'Auditoria & Compliance',
    title: 'Consolidação de Trilha de Auditoria do UniFi OS (Audit Log Central)',
    description: 'Captura de todos os logins, alterações de configuração e comandos executados por administradores no painel UniFi.',
    apiEndpoint: '/proxy/network/api/s/default/stat/alarm',
    impact: 'ALTO',
    valueProp: 'Garante a não-repúdio e rastreabilidade para auditorias forenses.'
  },
  {
    id: 16,
    category: 'Auditoria & Compliance',
    title: 'Teste Sintético de Isolamento de VLANs (VLAN Leak Tester)',
    description: 'Execução periódica de checagens para garantir que nenhuma rota entre a VLAN de Visitantes/IoT e a LAN principal esteja aberta.',
    apiEndpoint: '/proxy/network/api/s/default/rest/networkconf',
    impact: 'CRÍTICO',
    valueProp: 'Valida na prática a eficácia das regras de segmentação de rede.'
  },
  {
    id: 17,
    category: 'Auditoria & Compliance',
    title: 'Inventário Automatizado de Hardware e Números de Série',
    description: 'Mapeamento completo de números de série, MAC address, porta e versão de firmware de todos os switches e APs.',
    apiEndpoint: '/proxy/network/v2/api/site/default/device',
    impact: 'MÉDIO',
    valueProp: 'Gestão ágil do ciclo de vida de ativos de TI e garantia de equipamentos.'
  },
  {
    id: 18,
    category: 'Auditoria & Compliance',
    title: 'Alertas Proativos de Fim de Vida (EOL) e Patches Críticos',
    description: 'Notificação automática quando equipamentos instalados entram em ciclo EOL ou possuem correções de vulnerabilidade pendentes.',
    apiEndpoint: '/proxy/network/v2/api/site/default/device',
    impact: 'ALTO',
    valueProp: 'Previne o uso continuado de hardwares vulneráveis ou desatualizados.'
  },
  {
    id: 19,
    category: 'Auditoria & Compliance',
    title: 'Monitoramento Térmico e de Ventilação do UDM Pro',
    description: 'Acompanhamento de temperatura do processador e rotação das ventoinhas para evitar degradação do hardware.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sysinfo',
    impact: 'MÉDIO',
    valueProp: 'Evita desligamentos térmicos abruptos e estende a vida útil do gateway.'
  },
  {
    id: 20,
    category: 'Auditoria & Compliance',
    title: 'Backup de Configuração Criptografado Off-Site',
    description: 'Extração automatizada do arquivo de backup do UniFi OS e envio criptografado para um repositório em nuvem de sua escolha.',
    apiEndpoint: '/proxy/network/api/s/default/cmd/backup',
    impact: 'CRÍTICO',
    valueProp: 'Garante o Disaster Recovery (DR) do gateway em caso de falha física total.'
  },

  // 21-30: Análise Comportamental & IA
  {
    id: 21,
    category: 'Análise Comportamental & IA',
    title: 'Detecção de Exfiltração de Dados por Análise de Tráfego Massivo',
    description: 'Análise de curva normal de upload por dispositivo com alerta imediato se um host interno enviar volumes anômalos de GBs.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'CRÍTICO',
    valueProp: 'Identifica exfiltração de dados confidenciais por malware ou ameaças internas.'
  },
  {
    id: 22,
    category: 'Análise Comportamental & IA',
    title: 'Otimização Preditiva do Espectro Wi-Fi por IA',
    description: 'Análise diária dos níveis de interferência e taxas de retentativa de pacotes nos APs para sugerir o ajuste ideal de canais.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sysinfo',
    impact: 'MÉDIO',
    valueProp: 'Aumenta a velocidade e estabilidade da rede Wi-Fi sem necessidade de técnico no local.'
  },
  {
    id: 23,
    category: 'Análise Comportamental & IA',
    title: 'Classificação Avançada de IoTs por Impressão Digital (Fingerprinting)',
    description: 'Identificação do tipo exato do dispositivo (câmera, lâmpada inteligente, impressora) com base no comportamento de rede.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'MÉDIO',
    valueProp: 'Facilita a aplicação de políticas adequadas mesmo para dispositivos sem nome legível.'
  },
  {
    id: 24,
    category: 'Análise Comportamental & IA',
    title: 'Sumarização em Linguagem Natural de Alertas do IPS/IDS',
    description: 'Tradução automática de assinaturas complexas do Suricata/Snort em explicativos claros com plano de ação blue team.',
    apiEndpoint: '/proxy/network/api/s/default/stat/ips/event',
    impact: 'ALTO',
    valueProp: 'Permite que equipes de TI de todos os níveis compreendam a gravidade de cada ataque.'
  },
  {
    id: 25,
    category: 'Análise Comportamental & IA',
    title: 'Correlação Temporal entre Eventos de Rede e Servidores',
    description: 'Cruzamento dos horários de tentativas de invasão bloqueadas pelo UDM com os logs de autenticação de servidores internos.',
    apiEndpoint: '/proxy/network/api/s/default/stat/alarm',
    impact: 'ALTO',
    valueProp: 'Revela se um ataque externo obteve algum nível de sucesso na infraestrutura.'
  },
  {
    id: 26,
    category: 'Análise Comportamental & IA',
    title: 'Detecção de Beaconing de Malware para Servidores C2',
    description: 'Identificação de conexões periódicas e silenciosas originadas na rede em direção a IPs suspeitos na internet.',
    apiEndpoint: '/proxy/network/api/s/default/stat/ips/event',
    impact: 'CRÍTICO',
    valueProp: 'Detecta dispositivos infectados por botnets ou trojans de controle remoto.'
  },
  {
    id: 27,
    category: 'Análise Comportamental & IA',
    title: 'Score de Risco Dinâmico por Dispositivo Conectado (0 a 100)',
    description: 'Pontuação contínua calculada com base na versão do SO, consumo de dados, alertas IPS acionados e portas acessadas.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'ALTO',
    valueProp: 'Prioriza a atenção dos administradores nos dispositivos mais críticos da rede.'
  },
  {
    id: 28,
    category: 'Análise Comportamental & IA',
    title: 'Previsão de Sobrecarga e Gargalos em Access Points',
    description: 'Modelagem preditiva que antecipa em quais pontos de acesso haverá degradação de sinal com base no histórico de conexões.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'MÉDIO',
    valueProp: 'Permite o remanejamento preventivo de antenas antes de eventos e reuniões de grande porte.'
  },
  {
    id: 29,
    category: 'Análise Comportamental & IA',
    title: 'Detecção de Clonagem de Endereço MAC (MAC Spoofing)',
    description: 'Alerta instantâneo ao notar múltiplos IPs ativos ou oscilações atípicas atribuídas ao mesmo endereço físico.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'CRÍTICO',
    valueProp: 'Evita a burla de controles de segurança baseados no endereço MAC do dispositivo.'
  },
  {
    id: 30,
    category: 'Análise Comportamental & IA',
    title: 'Recomendação Automática de Microsegmentação com IA',
    description: 'A IA analisa a comunicação entre IPs e sugere a criação de regras de firewall otimizadas no menor privilégio.',
    apiEndpoint: '/proxy/network/api/s/default/rest/firewallrule',
    impact: 'ALTO',
    valueProp: 'Acelera a implementação de arquitetura Zero Trust na rede local.'
  },

  // 31-40: Visibilidade em Tempo Real
  {
    id: 31,
    category: 'Visibilidade em Tempo Real',
    title: 'Painel Centralizado NOC/SOC Multi-Site Unificado',
    description: 'Visualização agregada da saúde de múltiplos UDMs Pro e filiais em uma única interface operacional sem troca de login.',
    apiEndpoint: '/unifi-api/network',
    impact: 'ALTO',
    valueProp: 'Simplifica a gestão de MSSPs e empresas com múltiplas unidades regionais.'
  },
  {
    id: 32,
    category: 'Visibilidade em Tempo Real',
    title: 'Mapa de Calor de Tráfego de Banda por Categoria de Aplicação',
    description: 'Gráficos detalhados mostrando o consumo em tempo real de vídeos, conferências, jogos e transferências de arquivos.',
    apiEndpoint: '/proxy/network/api/s/default/stat/dpi',
    impact: 'MÉDIO',
    valueProp: 'Identifica com precisão quais serviços consomem o link de internet principal.'
  },
  {
    id: 33,
    category: 'Visibilidade em Tempo Real',
    title: 'Telemetria de Potência PoE por Porta de Switch',
    description: 'Exibição do consumo energético em Watts de cada câmera, telefone VoIP ou AP conectado nos switches do UDM.',
    apiEndpoint: '/proxy/network/v2/api/site/default/device',
    impact: 'MÉDIO',
    valueProp: 'Previne a sobrecarga no orçamento energético (PoE Budget) do equipamento.'
  },
  {
    id: 34,
    category: 'Visibilidade em Tempo Real',
    title: 'Rastreamento Detalhado do Histórico de Roaming Wi-Fi',
    description: 'Linha do tempo mostrando as transições de um celular entre antenas com registro do tempo de troca em milissegundos.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'MÉDIO',
    valueProp: 'Diagnostica desconexões em chamadas de voz ou terminais de coleta de dados móveis.'
  },
  {
    id: 35,
    category: 'Visibilidade em Tempo Real',
    title: 'Leitura Diagnóstica de Transceivers SFP+ e Fibra Óptica',
    description: 'Monitoramento da qualidade do sinal óptico (dBm) nas portas SFP+ de 10Gbps para evitar perdas de pacotes no uplink.',
    apiEndpoint: '/proxy/network/v2/api/site/default/device',
    impact: 'ALTO',
    valueProp: 'Identifica cabos de fibra sujos, curvados ou com perda de atenuador antes de cair o link.'
  },
  {
    id: 36,
    category: 'Visibilidade em Tempo Real',
    title: 'Portal de Analytics para Redes de Visitantes (Guest Insights)',
    description: 'Métricas sobre tempo médio de permanência de clientes, horário de pico de visitas e volume de dados consumido.',
    apiEndpoint: '/proxy/network/api/s/default/stat/guest',
    impact: 'MÉDIO',
    valueProp: 'Fornece inteligência de negócios relevante para varejo, restaurantes e escritórios.'
  },
  {
    id: 37,
    category: 'Visibilidade em Tempo Real',
    title: 'Diagnósticos Automáticos de Rota MTR/Traceroute em Quedas de WAN',
    description: 'Execução instantânea de testes de rota no exato segundo em que o gateway detectar perda de pacotes com a internet.',
    apiEndpoint: '/proxy/network/api/s/default/stat/health',
    impact: 'ALTO',
    valueProp: 'Fornece provas técnicas imediatas para cobrar a concessionária de internet (ISP).'
  },
  {
    id: 38,
    category: 'Visibilidade em Tempo Real',
    title: 'Matriz de Topologia Física e Detecção de Loops Spanning Tree',
    description: 'Mapeamento visual da hierarquia de switches e alertas imediatos se uma porta for bloqueada por loop de cabo.',
    apiEndpoint: '/proxy/network/v2/api/site/default/device',
    impact: 'CRÍTICO',
    valueProp: 'Localiza com exatidão qual porta físico travou o tráfego da empresa.'
  },
  {
    id: 39,
    category: 'Visibilidade em Tempo Real',
    title: 'Alertas de Servidores DHCP Não Autorizados (Rogue DHCP Detection)',
    description: 'Notificação imediata se um roteador doméstico ou equipamento externo começar a distribuir IPs inválidos na LAN.',
    apiEndpoint: '/proxy/network/api/s/default/stat/alarm',
    impact: 'CRÍTICO',
    valueProp: 'Evita a interrupção geral da rede causada pela injeção de gateways incorretos.'
  },
  {
    id: 40,
    category: 'Visibilidade em Tempo Real',
    title: 'Telemetria do Disco Rígido Interno do UDM Pro (S.M.A.R.T.)',
    description: 'Acompanhamento do estado de vida útil, temperatura e setores defeituosos do HD SATA utilizado no UniFi Protect.',
    apiEndpoint: '/unifi-api/network',
    impact: 'ALTO',
    valueProp: 'Evita a perda de gravações de câmeras de segurança por falha inesperada no HD.'
  },

  // 41-50: Integrações de Terceiros
  {
    id: 41,
    category: 'Integrações de Terceiros',
    title: 'Gatilhos de Automação Residencial e predial (Home Assistant / Node-RED)',
    description: 'Disparo de rotinas de iluminação, ar-condicionado e alarme ao detectar a chegada ou saída do smartphone do usuário.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sta',
    impact: 'MÉDIO',
    valueProp: 'Integra a presença de rede Wi-Fi com os sistemas de automação predial.'
  },
  {
    id: 42,
    category: 'Integrações de Terceiros',
    title: 'Encaminhamento Estruturado para SIEM (Splunk, Elastic, Datadog)',
    description: 'Exportação em formato JSON normalizado de todos os eventos de firewall, IPS e DHCP para plataformas de segurança corporativas.',
    apiEndpoint: '/proxy/network/api/s/default/stat/alarm',
    impact: 'CRÍTICO',
    valueProp: 'Atende às exigências de centralização de logs para equipes dedicadas de SOC.'
  },
  {
    id: 43,
    category: 'Integrações de Terceiros',
    title: 'Liberação de Acesso por Autenticação Multi-Fator (2FA Mobile)',
    description: 'Portal Web onde o administrador deve aprovar uma notificação no celular para liberar portas administrativas temporárias no firewall.',
    apiEndpoint: '/proxy/network/api/s/default/rest/firewallrule',
    impact: 'CRÍTICO',
    valueProp: 'Adiciona uma camada extra de proteção Zero-Trust contra acessos não autorizados.'
  },
  {
    id: 44,
    category: 'Integrações de Terceiros',
    title: 'Notificações Críticas de Incidentes via WhatsApp, Telegram e SMS',
    description: 'Envio de alertas com bot dedicado para mensagens instantâneas assim que o IPS bloquear um ataque grave ou o link WAN cair.',
    apiEndpoint: '/proxy/network/api/s/default/stat/ips/event',
    impact: 'ALTO',
    valueProp: 'Garante que a equipe de TI receba o aviso mesmo longe do computador do trabalho.'
  },
  {
    id: 45,
    category: 'Integrações de Terceiros',
    title: 'Abertura Automática de Chamados de Suporte (Jira / ServiceNow / GLPI)',
    description: 'Criação automática de tickets de atendimento quando um AP desconectar ou quando a memória do UDM ultrapassar 90%.',
    apiEndpoint: '/proxy/network/api/s/default/stat/alarm',
    impact: 'MÉDIO',
    valueProp: 'Reduz o tempo de atendimento (MTTR) integrando a rede ao fluxo da equipe de TI.'
  },
  {
    id: 46,
    category: 'Integrações de Terceiros',
    title: 'Sincronização Dinâmica com Provedores de DNS Seguro (NextDNS / Cloudflare)',
    description: 'Atualização automática do IP público nas configurações do filtro DNS externo sempre que o link WAN trocar de IP.',
    apiEndpoint: '/proxy/network/api/s/default/rest/networkconf',
    impact: 'MÉDIO',
    valueProp: 'Mantém o bloqueio de sites maliciosos e adultos sempre ativo na WAN.'
  },
  {
    id: 47,
    category: 'Integrações de Terceiros',
    title: 'Portal de Visitantes com Validação por Código via SMS / WhatsApp OTP',
    description: 'Sistema onde o convidado digita seu telefone, recebe um PIN de 4 dígitos via mensagem e tem o Wi-Fi liberado automaticamente.',
    apiEndpoint: '/proxy/network/api/s/default/cmd/stamgr',
    impact: 'MÉDIO',
    valueProp: 'Garante a identificação real dos usuários da rede pública atendendo a requisitos legais.'
  },
  {
    id: 48,
    category: 'Integrações de Terceiros',
    title: 'Controle Parental Programado com Regras Personalizadas',
    description: 'Agendamento de perfis de navegação para dispositivos infantis/estudantis, desativando redes sociais e jogos em horários de aula.',
    apiEndpoint: '/proxy/network/api/s/default/rest/firewallrule',
    impact: 'MÉDIO',
    valueProp: 'Oferece controle granular para ambientes residenciais e instituições de ensino.'
  },
  {
    id: 49,
    category: 'Integrações de Terceiros',
    title: 'Integração de Segurança Lógica com Segurança Física (UniFi Protect)',
    description: 'Cruzamento de alertas do firewall com gravação automática de vídeo do local da tomada de rede afetada.',
    apiEndpoint: '/unifi-api/network',
    impact: 'ALTO',
    valueProp: 'Associa um ataque de rede ao rosto da pessoa presente na sala no momento da intrusão.'
  },
  {
    id: 50,
    category: 'Integrações de Terceiros',
    title: 'Exportação de Relatórios de Auditoria Whitelabel em PDF/CSV',
    description: 'Geração de relatórios executivos de cibersegurança e desempenho com a marca da sua empresa prestadora de serviços.',
    apiEndpoint: '/proxy/network/api/s/default/stat/sysinfo',
    impact: 'ALTO',
    valueProp: 'Demonstra o valor dos serviços de gestão de TI de forma profissional para clientes.'
  }
];

const ApiCapabilitiesCatalog: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('TODAS');
  const [selectedItem, setSelectedItem] = useState<ApiCapability | null>(null);

  const categories = [
    'TODAS',
    'Automação & Orquestração',
    'Auditoria & Compliance',
    'Análise Comportamental & IA',
    'Visibilidade em Tempo Real',
    'Integrações de Terceiros'
  ];

  const filteredCapabilities = CAPABILITIES_DATA.filter(cap => {
    const matchesSearch = cap.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          cap.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          cap.apiEndpoint.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === 'TODAS' || cap.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-6">
      {/* Banner Intro */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-ubiquiti-950 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-ubiquiti-900/60 text-ubiquiti-300 border border-ubiquiti-700/50 text-xs font-semibold uppercase tracking-wider mb-3">
            <Zap className="w-3.5 h-3.5" /> Arquitetura Complementar de Valor Agregado
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            50 Recursos & Proteções Exclusivos via API UniFi OS
          </h2>
          <p className="text-slate-300 mt-2 text-sm sm:text-base leading-relaxed">
            Descubra as capacidades avançadas de segurança, automação, auditoria e inteligência que uma aplicação customizada integrada ao UDM Pro via API REST pode realizar além das funções padrão do UniFi OS.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col md:flex-row gap-4 justify-between items-center">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por termo, recurso ou endpoint..."
            className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-sans"
          />
        </div>

        {/* Category Pills */}
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                selectedCategory === cat
                  ? 'bg-ubiquiti-600 text-white shadow-md shadow-ubiquiti-900/50'
                  : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Capabilities Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredCapabilities.map((item) => (
          <div
            key={item.id}
            onClick={() => setSelectedItem(item)}
            className="bg-slate-900 border border-slate-800 hover:border-ubiquiti-600/60 rounded-xl p-5 shadow-lg transition-all cursor-pointer flex flex-col justify-between group hover:shadow-ubiquiti-950/30"
          >
            <div>
              <div className="flex justify-between items-start gap-2 mb-3">
                <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-ubiquiti-400">
                  #{item.id}
                </span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                  item.impact === 'CRÍTICO' ? 'bg-red-950/80 text-red-400 border-red-800/60' :
                  item.impact === 'ALTO' ? 'bg-orange-950/80 text-orange-400 border-orange-800/60' :
                  'bg-yellow-950/80 text-yellow-400 border-yellow-800/60'
                }`}>
                  IMPACTO {item.impact}
                </span>
              </div>

              <h3 className="font-bold text-white text-base group-hover:text-ubiquiti-400 transition-colors line-clamp-2 mb-2">
                {item.title}
              </h3>

              <p className="text-slate-400 text-xs leading-relaxed line-clamp-3 mb-4">
                {item.description}
              </p>
            </div>

            <div className="border-t border-slate-800/80 pt-3 mt-2 flex justify-between items-center text-xs">
              <span className="font-mono text-slate-500 truncate max-w-[200px]" title={item.apiEndpoint}>
                {item.apiEndpoint}
              </span>
              <span className="text-ubiquiti-400 font-semibold flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                Detalhes <ChevronRight className="w-3.5 h-3.5" />
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Modal / Detail View */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-5 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-start gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-slate-950 text-ubiquiti-400 border border-slate-800">
                    Recurso #{selectedItem.id}
                  </span>
                  <span className="text-xs text-slate-400 font-semibold px-2.5 py-1 rounded bg-slate-800">
                    {selectedItem.category}
                  </span>
                </div>
                <h3 className="text-xl font-bold text-white leading-snug">
                  {selectedItem.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="text-slate-400 hover:text-white text-xl font-bold p-1 bg-slate-950 rounded-lg border border-slate-800 hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-sm">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
                  Descrição Técnica do Serviço
                </span>
                <p className="text-slate-200 leading-relaxed">
                  {selectedItem.description}
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-semibold uppercase tracking-wider text-ubiquiti-400 block mb-1">
                  Diferencial & Valor de Negócio
                </span>
                <p className="text-slate-300 leading-relaxed">
                  {selectedItem.valueProp}
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-semibold uppercase tracking-wider text-yellow-400 block mb-1 font-mono">
                  Endpoint da API UniFi OS Utilizado
                </span>
                <code className="text-yellow-300 font-mono text-xs block bg-slate-900 p-2 rounded border border-slate-800">
                  {selectedItem.apiEndpoint}
                </code>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedItem(null)}
                className="bg-ubiquiti-600 hover:bg-ubiquiti-500 text-white font-semibold text-sm px-5 py-2.5 rounded-lg transition-all"
              >
                Fechar Detalhes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiCapabilitiesCatalog;
