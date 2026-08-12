import React, { useState } from 'react';
import {
  Wifi, ShieldAlert, Activity, AlertTriangle, Eye, Zap,
  RefreshCw, Terminal, Globe, Lock, Cpu, Server, Bot,
  ArrowUpRight, ArrowDownRight, ShieldCheck, FileWarning
} from 'lucide-react';

interface NetworkAnomaly {
  id: string;
  timestamp: string;
  type: 'EXFILTRATION' | 'DNS_ATTACK' | 'WIFI_DEAUTH' | 'ARP_SPOOFING';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  source: string;
  destination: string;
  details: string;
  recommendation: string;
}

const NetworkAnalyzer: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [loadingAi, setLoadingAi] = useState(false);

  const [anomalies, setAnomalies] = useState<NetworkAnomaly[]>([
    {
      id: 'anom-101',
      timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      type: 'EXFILTRATION',
      severity: 'CRITICAL',
      source: '192.168.30.22 (Smart-TV-Sala / IoT VLAN)',
      destination: '185.220.101.5 (IP da rede Tor / Rússia)',
      details: 'Upload anômalo contínuo de 12.4 GB de tráfego HTTPS em 15 minutos (volume histórico máximo anterior era de 50MB/dia). Suspeita de exfiltração de dados.',
      recommendation: 'Isolar imediatamente o dispositivo na porta do switch USW-24-PoE #18 ou bloquear o endereço MAC na controladora Wi-Fi.'
    },
    {
      id: 'anom-102',
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      type: 'DNS_ATTACK',
      severity: 'HIGH',
      source: '192.168.20.101 (Guest-iPhone-14 / Guest VLAN)',
      destination: '1.1.1.1 e 8.8.8.8 (Porta 53 UDP)',
      details: 'Alta taxa de consultas DNS anormais contendo payloads base64 gigantes (ex: x7g9a8s.tunnel.attacker.com). Padrão característico de DNS Tunneling (Burla de firewall e exfiltração).',
      recommendation: 'Habilitar inspeção profunda de pacotes (DPI), bloquear consultas DNS diretas de clientes para a WAN e forçar o uso do DNS interno do UDM Pro.'
    },
    {
      id: 'anom-103',
      timestamp: new Date(Date.now() - 32 * 60 * 1000).toISOString(),
      type: 'WIFI_DEAUTH',
      severity: 'HIGH',
      source: 'MAC Desconhecido (74:AC:B9:11:44:EE)',
      destination: 'U6-Pro-Escritorio (Canal 36 - 5GHz)',
      details: 'Rajada massiva de pacotes Wi-Fi Deauthentication (Deauth) falsificados para forçar clientes a se desconectarem. Ataque típico para clonagem de SSID (Evil Twin) ou negação de serviço Wi-Fi.',
      recommendation: 'Habilitar PMF (Protected Management Frames) em nível Obrigatório nas configurações de SSID WLAN do UniFi OS.'
    },
    {
      id: 'anom-104',
      timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
      type: 'ARP_SPOOFING',
      severity: 'MEDIUM',
      source: '192.168.1.155 (PC-Financeiro-Old / Corporate VLAN)',
      destination: '192.168.1.1 (UDM Pro Gateway)',
      details: 'Injeção de respostas ARP gratuitas na rede local afirmando possuir o IP do gateway. Suspeita de ataque Man-in-the-Middle (MitM / ARP Poisoning).',
      recommendation: 'Habilitar ARP Guard / DHCP Snooping no UniFi Switch Core para invalidar mapeamentos IP/MAC falsos.'
    }
  ]);

  const handleRunAiTrafficAudit = async () => {
    setLoadingAi(true);
    setAiReport(null);

    try {
      const response = await fetch('/api/udm/analyze-traffic', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ anomalies }),
      });

      const data = await response.json();
      if (data.success) {
        setAiReport(data.report);
      } else {
        setAiReport('Não foi possível gerar a análise por IA. Erro no backend.');
      }
    } catch (err: any) {
      setAiReport('Erro ao comunicar com o servidor proxy de IA: ' + err.message);
    } finally {
      setLoadingAi(false);
    }
  };

  const startTrafficScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      // Simular detecção de uma nova anomalia
      const newAnom: NetworkAnomaly = {
        id: 'anom-' + Math.floor(Math.random() * 900 + 100),
        timestamp: new Date().toISOString(),
        type: 'DNS_ATTACK',
        severity: 'HIGH',
        source: '192.168.1.80 (Desktop-Dev)',
        destination: '91.240.118.172 (DNS Desconhecido)',
        details: 'Tentativa de sequestro de DNS (DNS Hijacking) alterando o arquivo hosts ou configurações locais para redirecionar tráfego do banco corporativo.',
        recommendation: 'Verificar infecção por malware na estação e aplicar filtragem estrita de DNS no firewall do UDM Pro.'
      };
      setAnomalies(prev => [newAnom, ...prev]);
    }, 2000);
  };

  return (
    <div className="space-y-6">
      {/* Intro Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-red-950 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/80 text-red-400 border border-red-800/60 text-xs font-semibold uppercase tracking-wider mb-3">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" /> Monitoramento Avançado de Ameaças & Wi-Fi
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Análise de Rede, Intrusões Wi-Fi, Desvios de DNS e Exfiltração de Dados
          </h2>
          <p className="text-slate-300 mt-2 text-sm sm:text-base leading-relaxed">
            Identifique comportamentos anômalos que burlam firewalls tradicionais. Monitore conexões clandestinas de exfiltração por volumes massivos, ataques de desautenticação (Deauth) Wi-Fi, falsificações ARP e túneis DNS ocultos.
          </p>
        </div>
      </div>

      {/* Control Buttons and Simulator Status */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row gap-4 justify-between items-center">
        <div>
          <span className="text-xs font-bold uppercase text-slate-400 tracking-wider block">Estado do Analisador Real-Time</span>
          <div className="flex items-center gap-2 mt-1">
            <span className="relative flex h-3 w-3">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isScanning ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-3 w-3 ${isScanning ? 'bg-amber-500' : 'bg-emerald-500'}`}></span>
            </span>
            <span className="text-sm font-bold text-white">
              {isScanning ? 'Analisando Pacotes e Sinais Wi-Fi...' : 'Monitoramento de Rede Ativo'}
            </span>
          </div>
        </div>

        <div className="flex gap-2.5 w-full md:w-auto">
          <button
            onClick={startTrafficScan}
            disabled={isScanning}
            className="flex-1 md:flex-none bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-50 text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            Forçar Scan de Tráfego Wi-Fi/DNS
          </button>

          <button
            onClick={handleRunAiTrafficAudit}
            disabled={loadingAi}
            className="flex-1 md:flex-none bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-purple-900/30"
          >
            {loadingAi ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Bot className="w-3.5 h-3.5" />}
            Gerar Diagnóstico IA Blue Team
          </button>
        </div>
      </div>

      {/* Grid: Traffic Analytics Gauge Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric Card 1 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Consultas DNS / seg</span>
            <Globe className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white">412 req/s</div>
          <span className="text-[10px] text-yellow-500 mt-2 block font-medium">⚠️ Alerta: 22% de tráfego DNS não-resolvido</span>
        </div>

        {/* Metric Card 2 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Ataques Deauth Wi-Fi</span>
            <Wifi className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-black text-red-500">14 Quadros</div>
          <span className="text-[10px] text-red-400 mt-2 block font-medium">🚨 Ataque de desautenticação detectado em U6-Pro</span>
        </div>

        {/* Metric Card 3 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Taxa de Upload (WAN)</span>
            <ArrowUpRight className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">114.5 Mbps</div>
          <span className="text-[10px] text-emerald-500 mt-2 block font-medium">✓ Uso normal exceto VLAN IoT (Quarentena)</span>
        </div>

        {/* Metric Card 4 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Varredura ARP/Scan de Rede</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-white">Inativo</div>
          <span className="text-[10px] text-slate-500 mt-2 block">Proteções do Switch Core ativas</span>
        </div>
      </div>

      {/* Main Content Sections: Anomaly Logs & AI Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Anomalies List */}
        <div className="lg:col-span-8 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-500" />
              Console Técnico de Anomalias & Invasões
            </h3>

            <div className="space-y-4">
              {anomalies.map((anom) => (
                <div
                  key={anom.id}
                  className={`p-4 rounded-lg border transition-all ${
                    anom.severity === 'CRITICAL'
                      ? 'bg-red-950/20 border-red-900/60 hover:border-red-800'
                      : anom.severity === 'HIGH'
                      ? 'bg-orange-950/20 border-orange-900/60 hover:border-orange-800'
                      : 'bg-yellow-950/20 border-yellow-900/60 hover:border-yellow-800'
                  }`}
                >
                  <div className="flex justify-between items-start gap-4 mb-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                        anom.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' :
                        anom.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' :
                        'bg-yellow-950 text-yellow-400 border-yellow-800'
                      }`}>
                        {anom.severity}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {anom.type}
                      </span>
                      <span className="text-white font-bold text-sm">Origem: {anom.source}</span>
                    </div>
                    <span className="text-xs text-slate-500 font-mono shrink-0">
                      {new Date(anom.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-mono bg-slate-950/80 p-3 rounded border border-slate-800 mb-3">
                    {anom.details}
                  </p>

                  <div className="text-xs flex items-start gap-1 text-emerald-400 font-medium">
                    <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
                    <span><b>Recomendação Blue Team:</b> {anom.recommendation}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: AI Response & Technical Advice */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl h-full flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
                <Bot className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">IA Blue Team Guia</h3>
              </div>
              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Clique no botão superior direito para consolidar todas as anomalias detectadas em um plano de resposta técnica imediato gerado pelo Gemini.
              </p>

              {aiReport ? (
                <div className="bg-slate-950 rounded-lg p-4 border border-purple-800/40 text-xs text-slate-200 leading-relaxed whitespace-pre-wrap font-mono h-[380px] overflow-y-auto">
                  {aiReport}
                </div>
              ) : (
                <div className="bg-slate-950 rounded-lg p-8 border border-slate-800 text-center text-slate-500 text-xs flex flex-col items-center justify-center h-[380px] space-y-2">
                  <FileWarning className="w-8 h-8 text-slate-600 mb-1" />
                  <span>Nenhum relatório gerado no momento.</span>
                  <span>Clique em "Gerar Diagnóstico IA Blue Team" para rodar a análise avançada.</span>
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800/60 mt-4">
              <span className="text-[10px] font-mono text-slate-500 block text-center">
                Análise com IA generativa baseada em logs do Suricata, DNS e Wi-Fi do UDM.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkAnalyzer;
