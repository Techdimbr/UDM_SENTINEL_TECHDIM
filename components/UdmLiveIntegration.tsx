import React, { useState, useEffect } from 'react';
import { UDMSystemOverview, UDMDevice, UDMFirewallRule, UDMClient, UDMThreatEvent } from '../types';
import { 
  Shield, Server, Cpu, HardDrive, Wifi, Activity, AlertTriangle, CheckCircle2, 
  RefreshCw, Key, Globe, Network, Lock, Sliders, Zap, Bot, ArrowUpRight, ArrowDownRight, Eye, EyeOff
} from 'lucide-react';

const UdmLiveIntegration: React.FC = () => {
  // Configuration State
  const [host, setHost] = useState<string>('https://192.168.1.1');
  const [apiKey, setApiKey] = useState<string>('AudgaXGx6QNswXhxILrOatV_L-n5hBF1');
  const [showApiKey, setShowApiKey] = useState<boolean>(false);

  // Connection & Data States
  const [testingConnection, setTestingConnection] = useState<boolean>(false);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    message: string;
    isSimulated?: boolean;
    isLocalIp?: boolean;
  } | null>(null);

  const [activeSection, setActiveSection] = useState<'overview' | 'devices' | 'firewall' | 'clients' | 'threats' | 'audit'>('overview');
  const [loadingData, setLoadingData] = useState<boolean>(false);

  // Data
  const [overview, setOverview] = useState<UDMSystemOverview | null>(null);
  const [devices, setDevices] = useState<UDMDevice[]>([]);
  const [firewallRules, setFirewallRules] = useState<UDMFirewallRule[]>([]);
  const [clients, setClients] = useState<UDMClient[]>([]);
  const [threats, setThreats] = useState<UDMThreatEvent[]>([]);

  // AI Audit State
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditReport, setAuditReport] = useState<string | null>(null);

  // Initial Load
  useEffect(() => {
    testConnectionAndFetch();
  }, []);

  const getHeaders = () => ({
    'Content-Type': 'application/json',
    'x-udm-host': host,
    'x-udm-key': apiKey,
  });

  const testConnectionAndFetch = async () => {
    setTestingConnection(true);
    setLoadingData(true);
    try {
      // 1. Test Connection
      const testRes = await fetch('/api/udm/test', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ host, apiKey }),
      });
      const testData = await testRes.json();
      setConnectionStatus({
        connected: testData.connected,
        message: testData.message,
        isSimulated: testData.simulated,
        isLocalIp: testData.isLocalIp,
      });

      // 2. Fetch Data
      const [overviewRes, devicesRes, firewallRes, clientsRes, threatsRes] = await Promise.all([
        fetch('/api/udm/overview', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ host, apiKey }) }),
        fetch('/api/udm/devices', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ host, apiKey }) }),
        fetch('/api/udm/firewall', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ host, apiKey }) }),
        fetch('/api/udm/clients', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ host, apiKey }) }),
        fetch('/api/udm/threats', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ host, apiKey }) }),
      ]);

      const oData = await overviewRes.json();
      const dData = await devicesRes.json();
      const fData = await firewallRes.json();
      const cData = await clientsRes.json();
      const tData = await threatsRes.json();

      if (oData.data) setOverview(oData.data);
      if (dData.data) setDevices(dData.data);
      if (fData.data) setFirewallRules(fData.data);
      if (cData.data) setClients(cData.data);
      if (tData.data) setThreats(tData.data);

    } catch (err: any) {
      console.error('Error fetching UDM data:', err);
      setConnectionStatus({
        connected: false,
        message: 'Erro ao comunicar com a API do servidor proxy.',
        isSimulated: true,
      });
    } finally {
      setTestingConnection(false);
      setLoadingData(false);
    }
  };

  const handleRunAiAudit = async () => {
    setIsAuditing(true);
    setAuditReport(null);
    try {
      const res = await fetch('/api/udm/ai-audit', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          overview,
          firewall: firewallRules,
          threats,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setAuditReport(data.auditReport);
      } else {
        setAuditReport('Falha ao obter auditoria: ' + (data.error || 'Erro desconhecido.'));
      }
    } catch (err: any) {
      setAuditReport('Erro na comunicação com a API de auditoria de IA: ' + err.message);
    } finally {
      setIsAuditing(false);
    }
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    return `${days}d ${hours}h`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1024).toFixed(0) + ' KB';
  };

  return (
    <div className="space-y-6">
      {/* API Credentials Header Configuration */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4 mb-6 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-2 bg-ubiquiti-900/50 text-ubiquiti-400 rounded-lg border border-ubiquiti-800/50">
                <Network className="w-5 h-5" />
              </span>
              <h2 className="text-xl font-bold text-white">Conexão UniFi OS Network API</h2>
            </div>
            <p className="text-slate-400 text-sm mt-1">
              Endpoint: <code className="text-ubiquiti-400 font-mono text-xs bg-slate-950 px-2 py-0.5 rounded">/unifi-api/network</code> | Dispositivo: UDM Pro / UDM SE
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={testConnectionAndFetch}
              disabled={testingConnection}
              className="bg-ubiquiti-600 hover:bg-ubiquiti-500 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-ubiquiti-900/30"
            >
              <RefreshCw className={`w-4 h-4 ${testingConnection ? 'animate-spin' : ''}`} />
              {testingConnection ? 'Sincronizando...' : 'Testar e Atualizar API'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-5">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-ubiquiti-400" /> Host UDM Pro (IP / URL)
            </label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="https://192.168.1.1 ou https://udm.seudominio.com"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-white font-mono text-sm focus:outline-none focus:border-ubiquiti-500"
            />
          </div>

          <div className="md:col-span-7">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-yellow-400" /> Chave de API UniFi OS (X-API-KEY)
            </label>
            <div className="relative">
              <input
                type={showApiKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Insira sua API Key do UniFi OS"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-3.5 pr-10 py-2 text-white font-mono text-sm focus:outline-none focus:border-ubiquiti-500"
              />
              <button
                type="button"
                onClick={() => setShowApiKey(!showApiKey)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
              >
                {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>

        {/* Status Alert Banner */}
        {connectionStatus && (
          <div className={`mt-4 p-4 rounded-lg border text-sm flex items-start gap-3 ${
            connectionStatus.connected
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-slate-950 border-slate-800 text-slate-300'
          }`}>
            <div className="mt-0.5">
              {connectionStatus.connected ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              ) : (
                <Zap className="w-5 h-5 text-ubiquiti-400" />
              )}
            </div>
            <div className="flex-1 leading-relaxed">
              <div className="font-semibold text-white flex items-center gap-2">
                {connectionStatus.connected ? 'Conexão Direta Ativa' : 'Modo UniFi OS Proxy (Alta Fidelidade)'}
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-slate-800 text-slate-300 border border-slate-700">
                  {connectionStatus.connected ? 'LIVE API' : 'SIMULATED DATA'}
                </span>
              </div>
              <p className="mt-1 text-slate-300 text-xs">{connectionStatus.message}</p>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        {[
          { id: 'overview', label: 'Visão Geral & Métricas', icon: Server },
          { id: 'devices', label: 'Equipamentos Adotados', icon: Cpu },
          { id: 'firewall', label: 'Regras de Firewall', icon: Shield },
          { id: 'clients', label: 'Dispositivos na Rede', icon: Wifi },
          { id: 'threats', label: 'Ameaças e IPS/IDS', icon: AlertTriangle },
          { id: 'audit', label: 'Auditoria de IA UDM', icon: Bot },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSection === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSection(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-ubiquiti-600 text-white shadow-lg shadow-ubiquiti-900/40'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* SECTION CONTENT */}
      {loadingData ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <RefreshCw className="w-8 h-8 text-ubiquiti-500 animate-spin mx-auto mb-3" />
          <p className="text-slate-300 font-medium">Carregando dados da API do UDM Pro...</p>
        </div>
      ) : (
        <>
          {/* SECTION: OVERVIEW */}
          {activeSection === 'overview' && overview && (
            <div className="space-y-6">
              {/* Metrics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Status WAN / Internet</span>
                    <span className="p-2 bg-emerald-950/60 text-emerald-400 rounded-lg border border-emerald-900/50">
                      <Globe className="w-4 h-4" />
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white mb-1">{overview.wanIp}</div>
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>ISP: {overview.isp}</span>
                    <span className="text-emerald-400 font-semibold">{overview.latencyMs}ms</span>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Carga do Processador</span>
                    <span className="p-2 bg-ubiquiti-950/60 text-ubiquiti-400 rounded-lg border border-ubiquiti-900/50">
                      <Cpu className="w-4 h-4" />
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white mb-1">{overview.cpuUsage}%</div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2">
                    <div className="bg-ubiquiti-500 h-1.5 rounded-full" style={{ width: `${overview.cpuUsage}%` }}></div>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Memória RAM</span>
                    <span className="p-2 bg-purple-950/60 text-purple-400 rounded-lg border border-purple-900/50">
                      <Activity className="w-4 h-4" />
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white mb-1">{overview.memoryUsage}%</div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2">
                    <div className="bg-purple-500 h-1.5 rounded-full" style={{ width: `${overview.memoryUsage}%` }}></div>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Ameaças Bloqueadas</span>
                    <span className="p-2 bg-red-950/60 text-red-400 rounded-lg border border-red-900/50">
                      <AlertTriangle className="w-4 h-4" />
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white mb-1">{overview.activeThreatsCount} Deteções</div>
                  <div className="text-xs text-red-400 font-medium">IPS/IDS Ativo no Nível Máximo</div>
                </div>
              </div>

              {/* Hardware System Info Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Server className="w-5 h-5 text-ubiquiti-400" />
                  Especificações do Console UniFi OS
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 text-sm">
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Modelo do Equipamento</span>
                    <p className="text-white font-semibold text-base mt-1">{overview.model}</p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Versão do UniFi OS</span>
                    <p className="text-ubiquiti-400 font-mono font-semibold text-base mt-1">{overview.unifiOsVersion}</p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Tempo de Atividade (Uptime)</span>
                    <p className="text-white font-semibold text-base mt-1">{formatUptime(overview.uptime)}</p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Gateway IP (LAN)</span>
                    <p className="text-white font-mono font-semibold text-base mt-1">{overview.gatewayIp}</p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Dispositivos UniFi Adotados</span>
                    <p className="text-white font-semibold text-base mt-1">{overview.adoptedDevicesCount} Equipamentos</p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-slate-400 text-xs">Clientes Ativos na Rede</span>
                    <p className="text-white font-semibold text-base mt-1">{overview.connectedClientsCount} Dispositivos</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* SECTION: DEVICES */}
          {activeSection === 'devices' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Cpu className="w-5 h-5 text-ubiquiti-400" />
                Infraestrutura UniFi (Switches, Access Points, Gateways)
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-xs font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3.5">Nome do Dispositivo</th>
                      <th className="p-3.5">Modelo</th>
                      <th className="p-3.5">IP / MAC</th>
                      <th className="p-3.5">Firmware</th>
                      <th className="p-3.5">Portas Ativas</th>
                      <th className="p-3.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {devices.map((dev) => (
                      <tr key={dev.id} className="hover:bg-slate-800/50">
                        <td className="p-3.5 font-semibold text-white flex items-center gap-2">
                          <Server className="w-4 h-4 text-ubiquiti-400" />
                          {dev.name}
                        </td>
                        <td className="p-3.5 text-slate-300">{dev.model}</td>
                        <td className="p-3.5 font-mono text-xs text-slate-400">
                          {dev.ip}
                          <br />
                          <span className="text-slate-500">{dev.mac}</span>
                        </td>
                        <td className="p-3.5 font-mono text-xs text-slate-300">{dev.firmware}</td>
                        <td className="p-3.5">
                          {dev.portsTotal ? (
                            <span className="text-xs bg-slate-800 px-2.5 py-1 rounded border border-slate-700 text-slate-200">
                              {dev.portsActive} / {dev.portsTotal} Portas
                            </span>
                          ) : (
                            <span className="text-slate-500 text-xs">N/A (AP)</span>
                          )}
                        </td>
                        <td className="p-3.5">
                          <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            {dev.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SECTION: FIREWALL */}
          {activeSection === 'firewall' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <Shield className="w-5 h-5 text-ubiquiti-400" />
                    Regras do Firewall UDM Pro (UniFi Network)
                  </h3>
                  <p className="text-slate-400 text-xs mt-1">
                    Regras de filtragem ativas para WAN IN, LAN IN, e redes isoladas (VLANs).
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-xs font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3.5">Índice / Grupo</th>
                      <th className="p-3.5">Nome da Regra</th>
                      <th className="p-3.5">Ação</th>
                      <th className="p-3.5">Protocolo</th>
                      <th className="p-3.5">Origem -&gt; Destino / Porta</th>
                      <th className="p-3.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {firewallRules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-slate-800/50">
                        <td className="p-3.5 font-mono text-xs">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-ubiquiti-400 border border-slate-700 font-bold">
                            #{rule.ruleIndex}
                          </span>
                          <span className="block text-slate-500 text-[10px] mt-1">{rule.ruleset}</span>
                        </td>
                        <td className="p-3.5 font-semibold text-white">{rule.name}</td>
                        <td className="p-3.5">
                          <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                            rule.action === 'DROP' ? 'bg-red-950/80 text-red-400 border border-red-800/60' :
                            rule.action === 'REJECT' ? 'bg-orange-950/80 text-orange-400 border border-orange-800/60' :
                            'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                          }`}>
                            {rule.action}
                          </span>
                        </td>
                        <td className="p-3.5 font-mono text-xs text-slate-300">{rule.protocol}</td>
                        <td className="p-3.5 font-mono text-xs text-slate-400">
                          {rule.srcAddress || 'Qualquer'} -&gt; {rule.dstAddress || 'Qualquer'}
                          {rule.dstPort && <span className="text-yellow-400 block font-bold">Porta: {rule.dstPort}</span>}
                        </td>
                        <td className="p-3.5">
                          {rule.enabled ? (
                            <span className="text-xs text-emerald-400 font-medium">Habilitada</span>
                          ) : (
                            <span className="text-xs text-slate-500">Desabilitada</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SECTION: CLIENTS */}
          {activeSection === 'clients' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Wifi className="w-5 h-5 text-ubiquiti-400" />
                Dispositivos Conectados e Consumo de Banda
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-xs font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3.5">Nome / Hostname</th>
                      <th className="p-3.5">IP / MAC</th>
                      <th className="p-3.5">Rede / VLAN</th>
                      <th className="p-3.5">Conexão</th>
                      <th className="p-3.5">Download / Upload</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {clients.map((cli) => (
                      <tr key={cli.id} className="hover:bg-slate-800/50">
                        <td className="p-3.5 font-semibold text-white">{cli.hostname}</td>
                        <td className="p-3.5 font-mono text-xs text-slate-400">
                          {cli.ip}
                          <br />
                          <span className="text-slate-500">{cli.mac}</span>
                        </td>
                        <td className="p-3.5 text-xs">
                          <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700">
                            {cli.network} (VLAN {cli.vlan})
                          </span>
                        </td>
                        <td className="p-3.5 text-xs">
                          {cli.connectionType === 'WIRELESS' ? (
                            <span className="text-ubiquiti-400 flex items-center gap-1 font-medium">
                              <Wifi className="w-3.5 h-3.5" /> Wi-Fi ({cli.signalDbm} dBm)
                            </span>
                          ) : (
                            <span className="text-emerald-400 flex items-center gap-1 font-medium">
                              <Network className="w-3.5 h-3.5" /> Cabeado
                            </span>
                          )}
                        </td>
                        <td className="p-3.5 font-mono text-xs">
                          <span className="text-emerald-400 flex items-center gap-1">
                            <ArrowDownRight className="w-3.5 h-3.5" /> {formatBytes(cli.rxBytes)}
                          </span>
                          <span className="text-blue-400 flex items-center gap-1">
                            <ArrowUpRight className="w-3.5 h-3.5" /> {formatBytes(cli.txBytes)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SECTION: THREATS */}
          {activeSection === 'threats' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-500" />
                Alertas de Intrusão IPS/IDS Deteções Recentes
              </h3>
              <div className="space-y-3">
                {threats.map((threat) => (
                  <div key={threat.id} className="p-4 bg-slate-950 rounded-lg border border-slate-800 hover:border-slate-700 transition-all">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                          threat.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                          threat.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                          'bg-yellow-950 text-yellow-400 border border-yellow-800'
                        }`}>
                          {threat.severity}
                        </span>
                        <span className="text-white font-semibold text-sm">{threat.category}</span>
                      </div>
                      <span className="text-slate-500 font-mono text-xs">{new Date(threat.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-xs font-mono text-slate-300 bg-slate-900 p-2.5 rounded border border-slate-800/80 mb-2">
                      {threat.signature}
                    </p>
                    <div className="flex justify-between items-center text-xs text-slate-400 font-mono">
                      <span>Origem: <strong className="text-red-400">{threat.srcIp}</strong> -&gt; Destino: <strong className="text-slate-200">{threat.dstIp}:{threat.dstPort}</strong></span>
                      <span className="text-emerald-400 font-bold px-2 py-0.5 bg-emerald-950/80 rounded border border-emerald-900">
                        AÇÃO: {threat.actionTaken}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SECTION: AI AUDIT */}
          {activeSection === 'audit' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
              <div>
                <h3 className="text-xl font-bold text-white flex items-center gap-2 mb-2">
                  <Bot className="w-6 h-6 text-purple-400" />
                  Auditoria Automatizada de Segurança com Inteligência Artificial
                </h3>
                <p className="text-slate-400 text-sm">
                  O motor de IA analisa todas as configurações de rede, regras de firewall e alertas IPS/IDS do seu UDM Pro para gerar um relatório completo de hardening.
                </p>
              </div>

              <button
                onClick={handleRunAiAudit}
                disabled={isAuditing}
                className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold py-3 px-4 rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-purple-900/40"
              >
                {isAuditing ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    Analisando Configurações do UDM Pro...
                  </>
                ) : (
                  <>
                    <Bot className="w-5 h-5" />
                    Gerar Relatório Completo de Auditoria UDM Pro
                  </>
                )}
              </button>

              {auditReport && (
                <div className="bg-slate-950 rounded-xl p-6 border border-purple-800/40 shadow-inner">
                  <h4 className="text-purple-400 font-bold text-sm uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Shield className="w-4 h-4" /> Relatório Executivo de Auditoria UDM Pro
                  </h4>
                  <div className="text-slate-200 text-sm leading-relaxed whitespace-pre-wrap font-sans">
                    {auditReport}
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default UdmLiveIntegration;
