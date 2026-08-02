import { NmapOption, SecurityCheckItem } from './types';

export const NMAP_OPTIONS: NmapOption[] = [
  { id: 'syn', flag: '-sS', label: 'TCP SYN Scan', description: 'Rápido e discreto (Scan Padrão).', category: 'basic' },
  { id: 'ver', flag: '-sV', label: 'Service Version', description: 'Detecta versões dos serviços rodando nas portas.', category: 'basic' },
  { id: 'os', flag: '-O', label: 'OS Detection', description: 'Tenta identificar o Sistema Operacional (UniFi OS).', category: 'advanced' },
  { id: 'allports', flag: '-p-', label: 'All Ports', description: 'Escaneia todas as 65535 portas (Lento).', category: 'advanced' },
  { id: 'skip', flag: '-Pn', label: 'Skip Ping', description: 'Assume que o host está online (útil se o firewall bloqueia ICMP).', category: 'basic' },
  { id: 'timing', flag: '-T4', label: 'Timing Aggressive', description: 'Acelera o scan (pode ser detectado pelo IPS do UDM).', category: 'aggressive' },
  { id: 'vuln', flag: '--script vuln', label: 'Vuln Scripts', description: 'Roda scripts Lua para detectar vulnerabilidades conhecidas (Barulhento).', category: 'aggressive' },
];

export const INITIAL_CHECKLIST: SecurityCheckItem[] = [
  { id: '1', title: 'Desativar Acesso Remoto SSH', description: 'Se não for usar, desative o SSH nas configurações do Console.', criticality: 'high', checked: false },
  { id: '2', title: 'Habilitar IPS/IDS', description: 'Ative o Intrusion Prevention System no nível máximo ou recomendado.', criticality: 'high', checked: false },
  { id: '3', title: 'Segregar IoT em VLAN', description: 'Crie uma VLAN isolada para dispositivos IoT e bloqueie acesso à LAN principal.', criticality: 'medium', checked: false },
  { id: '4', title: 'Regras de Firewall GeoIP', description: 'Bloqueie tráfego de entrada de países onde você não tem operações (Country Restriction).', criticality: 'medium', checked: false },
  { id: '5', title: 'Auditoria de Admins', description: 'Remova usuários antigos e force MFA (Autenticação de Dois Fatores) para todos.', criticality: 'high', checked: false },
  { id: '6', title: 'Update Automático', description: 'Configure atualizações automáticas ou verifique semanalmente o UniFi OS.', criticality: 'low', checked: false },
];