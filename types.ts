export enum Tab {
  LIVE_UDM = 'LIVE_UDM',
  EVENT_WIFI = 'EVENT_WIFI',
  REPORTS = 'REPORTS',
  CATALOG = 'CATALOG',
  GENERATOR = 'GENERATOR',
  ADVISOR = 'ADVISOR',
  CHECKLIST = 'CHECKLIST',
}

export interface WhitelabelConfig {
  companyName: string;
  companyLogoUrl: string;
  auditorName: string;
  auditorTitle: string;
  clientName: string;
  reportTitle: string;
  customNotes: string;
  includeAiAudit: boolean;
  includeFirewallRules: boolean;
  includeDeviceInventory: boolean;
  includeThreatLog: boolean;
  includeWifiEventConfig: boolean;
}

export interface WifiEventConfig {
  eventName: string;
  targetVisitors: number;
  neighborSsidsCount: number;
  channelWidth2g: '20MHz' | '40MHz';
  channelWidth5g: '20MHz' | '40MHz' | '80MHz';
  channelWidth6g: '20MHz' | '40MHz' | '80MHz' | '160MHz';
  minRssiDb: number;
  fastRoamingEnabled: boolean;
  bandSteering: 'OFF' | 'PREFER_5G' | 'FORCE_5G_6G';
  dhcpLeaseTimeMinutes: number;
  clientIsolation: boolean;
  multicastRateLimiting: boolean;
  broadcastFilter: boolean;
  guestRateLimitDownMbps: number;
  guestRateLimitUpMbps: number;
  airtimeFairness: boolean;
  apLoadBalancingThreshold: number;
}

export interface ApiCapability {
  id: number;
  category: 'Automação & Orquestração' | 'Auditoria & Compliance' | 'Análise Comportamental & IA' | 'Visibilidade em Tempo Real' | 'Integrações de Terceiros';
  title: string;
  description: string;
  apiEndpoint: string;
  impact: 'CRÍTICO' | 'ALTO' | 'MÉDIO';
  valueProp: string;
}

export interface UDMConfig {
  host: string;
  apiKey: string;
  useProxy: boolean;
}

export interface UDMSystemOverview {
  name: string;
  model: string;
  version: string;
  unifiOsVersion: string;
  uptime: number;
  cpuUsage: number;
  memoryUsage: number;
  storageUsage: number;
  wanIp: string;
  wanStatus: 'CONNECTED' | 'DISCONNECTED' | 'DEGRADED';
  gatewayIp: string;
  isp: string;
  latencyMs: number;
  connectedClientsCount: number;
  adoptedDevicesCount: number;
  activeThreatsCount: number;
}

export interface UDMDevice {
  id: string;
  name: string;
  model: string;
  ip: string;
  mac: string;
  status: 'ONLINE' | 'OFFLINE' | 'PENDING';
  type: 'GATEWAY' | 'SWITCH' | 'AP' | 'CAMERA';
  firmware: string;
  uptime: number;
  portsTotal?: number;
  portsActive?: number;
}

export interface UDMFirewallRule {
  id: string;
  ruleset: 'WAN_IN' | 'WAN_OUT' | 'LAN_IN' | 'LAN_LOCAL' | 'GUEST_IN';
  ruleIndex: number;
  action: 'ACCEPT' | 'DROP' | 'REJECT';
  protocol: 'ALL' | 'TCP' | 'UDP' | 'ICMP';
  name: string;
  enabled: boolean;
  srcAddress?: string;
  dstAddress?: string;
  dstPort?: string;
}

export interface UDMClient {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  network: string;
  vlan: number;
  connectionType: 'WIRELESS' | 'WIRED';
  signalDbm?: number;
  rxBytes: number;
  txBytes: number;
  firstSeen: string;
}

export interface UDMThreatEvent {
  id: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  srcIp: string;
  dstIp: string;
  dstPort: number;
  protocol: string;
  actionTaken: 'BLOCKED' | 'ALERTED';
  signature: string;
}

export interface NmapOption {
  id: string;
  flag: string;
  label: string;
  description: string;
  category: 'basic' | 'advanced' | 'aggressive';
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestamp: number;
}

export interface SecurityCheckItem {
  id: string;
  title: string;
  description: string;
  criticality: 'high' | 'medium' | 'low';
  checked: boolean;
}