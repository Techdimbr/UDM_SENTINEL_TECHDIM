import React, { useState } from 'react';
import { WifiEventConfig, UDMConfig } from '../types';
import { 
  Wifi, Zap, ShieldCheck, AlertOctagon, Sliders, Activity, Cpu, 
  Layers, Users, Radio, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpRight, Flame, Server
} from 'lucide-react';

interface Props {
  udmConfig?: UDMConfig;
}

const WifiEventOptimizer: React.FC<Props> = ({ udmConfig }) => {
  const [config, setConfig] = useState<WifiEventConfig>({
    eventName: 'Mega Evento Arena & Exposição',
    targetVisitors: 10000,
    neighborSsidsCount: 500,
    channelWidth2g: '20MHz',
    channelWidth5g: '20MHz',
    channelWidth6g: '40MHz',
    minRssiDb: -75,
    fastRoamingEnabled: true,
    bandSteering: 'FORCE_5G_6G',
    dhcpLeaseTimeMinutes: 15,
    clientIsolation: true,
    multicastRateLimiting: true,
    broadcastFilter: true,
    guestRateLimitDownMbps: 5,
    guestRateLimitUpMbps: 2,
    airtimeFairness: true,
    apLoadBalancingThreshold: 80,
  });

  const [applying, setApplying] = useState(false);
  const [applyResult, setApplyResult] = useState<{ success: boolean; message: string; details?: any } | null>(null);

  // Preset Handlers
  const applyPreset = (type: 'MEGA_10K' | 'CONFERENCE_3K' | 'STADIUM_15K') => {
    if (type === 'MEGA_10K') {
      setConfig({
        eventName: 'Mega Evento (10.000+ Visitantes / 500 SSIDs Vizinhas)',
        targetVisitors: 10000,
        neighborSsidsCount: 500,
        channelWidth2g: '20MHz',
        channelWidth5g: '20MHz',
        channelWidth6g: '40MHz',
        minRssiDb: -75,
        fastRoamingEnabled: true,
        bandSteering: 'FORCE_5G_6G',
        dhcpLeaseTimeMinutes: 15,
        clientIsolation: true,
        multicastRateLimiting: true,
        broadcastFilter: true,
        guestRateLimitDownMbps: 5,
        guestRateLimitUpMbps: 2,
        airtimeFairness: true,
        apLoadBalancingThreshold: 75,
      });
    } else if (type === 'CONFERENCE_3K') {
      setConfig({
        eventName: 'Convenção Corporativa (3.000 Usuários)',
        targetVisitors: 3000,
        neighborSsidsCount: 150,
        channelWidth2g: '20MHz',
        channelWidth5g: '40MHz',
        channelWidth6g: '80MHz',
        minRssiDb: -72,
        fastRoamingEnabled: true,
        bandSteering: 'PREFER_5G',
        dhcpLeaseTimeMinutes: 30,
        clientIsolation: true,
        multicastRateLimiting: true,
        broadcastFilter: true,
        guestRateLimitDownMbps: 10,
        guestRateLimitUpMbps: 5,
        airtimeFairness: true,
        apLoadBalancingThreshold: 85,
      });
    } else if (type === 'STADIUM_15K') {
      setConfig({
        eventName: 'Arena & Estádio (15.000+ Densidade Extrema)',
        targetVisitors: 15000,
        neighborSsidsCount: 650,
        channelWidth2g: '20MHz',
        channelWidth5g: '20MHz',
        channelWidth6g: '20MHz',
        minRssiDb: -70,
        fastRoamingEnabled: true,
        bandSteering: 'FORCE_5G_6G',
        dhcpLeaseTimeMinutes: 10,
        clientIsolation: true,
        multicastRateLimiting: true,
        broadcastFilter: true,
        guestRateLimitDownMbps: 3,
        guestRateLimitUpMbps: 1,
        airtimeFairness: true,
        apLoadBalancingThreshold: 70,
      });
    }
  };

  // Mathematical RF & Capacity Calculations
  const estimatedApsNeeded = Math.ceil(config.targetVisitors / 120); // ~120 clients per high density AP
  const coChannelInterferenceRisk = Math.min(100, Math.round((config.neighborSsidsCount / 500) * 85));
  const channelWidthPenalty = config.channelWidth5g === '80MHz' ? 40 : config.channelWidth5g === '40MHz' ? 20 : 0;
  const overallStabilityIndex = Math.max(10, Math.min(99, Math.round(
    100 
    - (coChannelInterferenceRisk * 0.4) 
    - channelWidthPenalty 
    + (config.clientIsolation ? 15 : -20)
    + (config.broadcastFilter ? 10 : -15)
    + (config.minRssiDb >= -75 ? 10 : -10)
  )));

  // Send config to backend API
  const handleApplyConfig = async () => {
    setApplying(true);
    setApplyResult(null);

    try {
      const response = await fetch('/api/udm/apply-wifi-high-density', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-udm-host': udmConfig?.host || '',
          'x-udm-key': udmConfig?.apiKey || ''
        },
        body: JSON.stringify({ config })
      });

      const data = await response.json();
      setApplyResult(data);
    } catch (err: any) {
      setApplyResult({
        success: false,
        message: 'Falha na comunicação com o servidor: ' + err.message
      });
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner Intro */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-ubiquiti-950 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-950/80 text-orange-400 border border-orange-800/60 text-xs font-semibold uppercase tracking-wider mb-3">
            <Flame className="w-3.5 h-3.5 text-orange-400" /> Solução para Eventos de Alta Densidade
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Otimizador Wi-Fi para 10.000+ Dispositivos & 500 SSIDs Vizinhas
          </h2>
          <p className="text-slate-300 mt-2 text-sm sm:text-base leading-relaxed">
            Elimine quedas, travamentos e exaustão de IPs em ambientes de altíssima interferência. Configure e aplique em tempo real o perfil de RF ideal para grandes feiras, arenas e congressos via API do UniFi OS.
          </p>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
        <span className="text-xs font-bold uppercase text-slate-400 tracking-wider block">
          Perfis de Alta Densidade Pré-Configurados (Presets)
        </span>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <button
            onClick={() => applyPreset('MEGA_10K')}
            className="bg-slate-950 border border-slate-800 hover:border-ubiquiti-500 p-4 rounded-xl text-left transition-all group"
          >
            <div className="flex justify-between items-start">
              <span className="text-sm font-bold text-white group-hover:text-ubiquiti-400">
                10.000+ Visitantes
              </span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                500 SSIDs Vizinhas
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Largura de canal 20MHz, Isolamento L2/L3, Min RSSI -75dBm, Lease DHCP de 15min.
            </p>
          </button>

          <button
            onClick={() => applyPreset('CONFERENCE_3K')}
            className="bg-slate-950 border border-slate-800 hover:border-ubiquiti-500 p-4 rounded-xl text-left transition-all group"
          >
            <div className="flex justify-between items-start">
              <span className="text-sm font-bold text-white group-hover:text-ubiquiti-400">
                3.000 Convenções
              </span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800">
                150 SSIDs Vizinhas
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Canal de 40MHz em 5GHz, Band Steering para 5GHz, Bandwidth de 10 Mbps por cliente.
            </p>
          </button>

          <button
            onClick={() => applyPreset('STADIUM_15K')}
            className="bg-slate-950 border border-slate-800 hover:border-ubiquiti-500 p-4 rounded-xl text-left transition-all group"
          >
            <div className="flex justify-between items-start">
              <span className="text-sm font-bold text-white group-hover:text-ubiquiti-400">
                15.000+ Estádio / Arena
              </span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
                650 SSIDs Vizinhas
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Forçar 5G/6G, Min RSSI agressivo -70dBm, Filtro estrito de Broadcast/Multicast.
            </p>
          </button>
        </div>
      </div>

      {/* Real-time Metric Gauges & RF Simulator */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Índice de Estabilidade Wi-Fi</span>
            <Activity className="w-4 h-4 text-ubiquiti-400" />
          </div>
          <div className="text-2xl font-black text-white">
            {overallStabilityIndex}%
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2 mt-2 overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 ${
                overallStabilityIndex >= 80 ? 'bg-emerald-500' :
                overallStabilityIndex >= 60 ? 'bg-yellow-500' : 'bg-red-500'
              }`}
              style={{ width: `${overallStabilityIndex}%` }}
            />
          </div>
          <span className="text-[10px] text-slate-500 mt-2 block">
            {overallStabilityIndex >= 80 ? 'Excelente para 10 mil conexões simultâneas' : 'Risco de degradação sob alta carga'}
          </span>
        </div>

        {/* Metric 2 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">APs Necessários Estimados</span>
            <Radio className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white">
            ~{estimatedApsNeeded} APs UniFi U6
          </div>
          <span className="text-xs text-slate-400 mt-1 block">
            Base: ~120 clientes ativados por ponto de acesso.
          </span>
        </div>

        {/* Metric 3 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Ruído / SSIDs Vizinhos</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-black text-orange-400">
            {config.neighborSsidsCount} SSIDs
          </div>
          <span className="text-xs text-slate-400 mt-1 block">
            Interferência Co-Canal Altíssima (CCI).
          </span>
        </div>

        {/* Metric 4 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase">Gargalo Evitado</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">
            {config.clientIsolation ? 'Sem Tempestade L2' : 'Tráfego Aberto'}
          </div>
          <span className="text-xs text-slate-400 mt-1 block">
            {config.broadcastFilter ? 'Multicast/mDNS Filtrado' : 'Aviso: mDNS liberado'}
          </span>
        </div>
      </div>

      {/* Main Form Configuration Panels */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
        <h3 className="text-lg font-bold text-white border-b border-slate-800 pb-3 flex items-center gap-2">
          <Sliders className="w-5 h-5 text-ubiquiti-400" /> Parâmetros Avançados da API de RF & WLAN
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Target Visitors */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Visitantes Simultâneos Esperados
            </label>
            <input
              type="number"
              value={config.targetVisitors}
              onChange={(e) => setConfig({ ...config, targetVisitors: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono font-bold"
            />
          </div>

          {/* Neighbor SSIDs */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Redes Wi-Fi Vizinhas Interferentes
            </label>
            <input
              type="number"
              value={config.neighborSsidsCount}
              onChange={(e) => setConfig({ ...config, neighborSsidsCount: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono font-bold text-orange-400"
            />
          </div>

          {/* Min RSSI */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Minimum RSSI (Desconectar Clientes Fracos)
            </label>
            <select
              value={config.minRssiDb}
              onChange={(e) => setConfig({ ...config, minRssiDb: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono"
            >
              <option value={-80}>-80 dBm (Permissivo / Longe)</option>
              <option value={-75}>-75 dBm (Recomendado Alta Densidade)</option>
              <option value={-72}>-72 dBm (Agressivo / Estádios)</option>
              <option value={-68}>-68 dBm (Ultra Agressivo)</option>
            </select>
          </div>

          {/* Channel Width 2.4GHz */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Largura de Canal 2.4GHz (Obrigatório 20MHz)
            </label>
            <select
              value={config.channelWidth2g}
              onChange={(e) => setConfig({ ...config, channelWidth2g: e.target.value as any })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono"
            >
              <option value="20MHz">20 MHz (Essencial para Evitar Colisão)</option>
              <option value="40MHz">40 MHz (Não Recomendado em Eventos)</option>
            </select>
          </div>

          {/* Channel Width 5GHz */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Largura de Canal 5GHz (Recomendado 20MHz ou 40MHz)
            </label>
            <select
              value={config.channelWidth5g}
              onChange={(e) => setConfig({ ...config, channelWidth5g: e.target.value as any })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono"
            >
              <option value="20MHz">20 MHz (Máxima Reutilização de Canais)</option>
              <option value="40MHz">40 MHz (Balanço Largura / Interferência)</option>
              <option value="80MHz">80 MHz (Alta Interferência se houver 500 SSIDs)</option>
            </select>
          </div>

          {/* Band Steering */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Band Steering (Direcionamento para 5G/6G)
            </label>
            <select
              value={config.bandSteering}
              onChange={(e) => setConfig({ ...config, bandSteering: e.target.value as any })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500"
            >
              <option value="FORCE_5G_6G font-bold">Forçar 5GHz / 6GHz (Liberar 2.4G)</option>
              <option value="PREFER_5G">Preferir 5GHz</option>
              <option value="OFF">Desativado</option>
            </select>
          </div>

          {/* DHCP Lease Time */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Tempo de Concessão DHCP (Evitar Exaustão de IPs)
            </label>
            <select
              value={config.dhcpLeaseTimeMinutes}
              onChange={(e) => setConfig({ ...config, dhcpLeaseTimeMinutes: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono font-bold"
            >
              <option value={10}>10 Minutos (Altíssimo Turnover)</option>
              <option value={15}>15 Minutos (Padrão Recomendado Eventos)</option>
              <option value={30}>30 Minutos</option>
              <option value={1440}>24 Horas (Risco de Falta de IPs)</option>
            </select>
          </div>

          {/* Guest Limits Down */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Limite de Download por Visitante (QoS)
            </label>
            <select
              value={config.guestRateLimitDownMbps}
              onChange={(e) => setConfig({ ...config, guestRateLimitDownMbps: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono"
            >
              <option value={3}>3 Mbps (Apenas Mensagens e Redes Sociais)</option>
              <option value={5}>5 Mbps (Ideal para 10.000 Visitantes)</option>
              <option value={10}>10 Mbps (Conferências Técnicas)</option>
              <option value={0}>Sem Limite (Não Recomendado)</option>
            </select>
          </div>

          {/* Guest Limits Up */}
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
              Limite de Upload por Visitante (QoS)
            </label>
            <select
              value={config.guestRateLimitUpMbps}
              onChange={(e) => setConfig({ ...config, guestRateLimitUpMbps: Number(e.target.value) })}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-mono"
            >
              <option value={1}>1 Mbps</option>
              <option value={2}>2 Mbps (Ideal para Fotos/Stories)</option>
              <option value={5}>5 Mbps</option>
            </select>
          </div>
        </div>

        {/* Feature Checkboxes */}
        <div className="border-t border-slate-800 pt-5">
          <h4 className="text-sm font-bold text-white mb-3">Mecanismos Ativos de Proteção contra Colapso de RF</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={config.clientIsolation}
                onChange={(e) => setConfig({ ...config, clientIsolation: e.target.checked })}
                className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
              />
              <div>
                <span className="text-xs font-bold text-white block">Isolamento de Clientes (L2/L3)</span>
                <span className="text-[10px] text-slate-400">Impede tráfego dispositivo a dispositivo</span>
              </div>
            </label>

            <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={config.broadcastFilter}
                onChange={(e) => setConfig({ ...config, broadcastFilter: e.target.checked })}
                className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
              />
              <div>
                <span className="text-xs font-bold text-white block">Bloqueio de Broadcast / mDNS</span>
                <span className="text-[10px] text-slate-400">Elimina tempestades de pacotes ARP</span>
              </div>
            </label>

            <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={config.fastRoamingEnabled}
                onChange={(e) => setConfig({ ...config, fastRoamingEnabled: e.target.checked })}
                className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
              />
              <div>
                <span className="text-xs font-bold text-white block">Fast Roaming (802.11r/k/v)</span>
                <span className="text-[10px] text-slate-400">Troca instantânea de APs em ms</span>
              </div>
            </label>

            <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={config.airtimeFairness}
                onChange={(e) => setConfig({ ...config, airtimeFairness: e.target.checked })}
                className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
              />
              <div>
                <span className="text-xs font-bold text-white block">Airtime Fairness</span>
                <span className="text-[10px] text-slate-400">Impede que 1 cliente lento trave o AP</span>
              </div>
            </label>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex flex-col sm:flex-row justify-between items-center gap-4 border-t border-slate-800 pt-5">
          <div className="text-xs text-slate-400">
            <span className="text-white font-bold block">Status da Aplicação de Regras:</span>
            Configurações prontas para serem enviadas via REST API ao endpoint <code className="text-ubiquiti-400">/rest/wlanconf</code> do UDM Pro.
          </div>

          <button
            onClick={handleApplyConfig}
            disabled={applying}
            className="w-full sm:w-auto bg-ubiquiti-600 hover:bg-ubiquiti-500 disabled:bg-slate-800 text-white font-bold text-sm px-8 py-3 rounded-xl shadow-lg shadow-ubiquiti-950/50 flex items-center justify-center gap-2 transition-all"
          >
            {applying ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-white" /> Aplicando via API UniFi OS...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 text-yellow-300" /> Aplicar Perfil de Alta Densidade no UDM Pro
              </>
            )}
          </button>
        </div>

        {/* Result Message */}
        {applyResult && (
          <div className={`p-4 rounded-xl border text-xs space-y-2 animate-in fade-in ${
            applyResult.success 
              ? 'bg-emerald-950/80 border-emerald-800 text-emerald-200' 
              : 'bg-red-950/80 border-red-800 text-red-200'
          }`}>
            <div className="flex items-center gap-2 font-bold text-sm">
              {applyResult.success ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <AlertTriangle className="w-5 h-5 text-red-400" />}
              {applyResult.message}
            </div>
            {applyResult.details && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-emerald-800/60 font-mono text-[11px]">
                <div>2.4GHz: <b>{applyResult.details.channelWidth2g}</b></div>
                <div>5GHz: <b>{applyResult.details.channelWidth5g}</b></div>
                <div>Min RSSI: <b>{applyResult.details.minRssiDb} dBm</b></div>
                <div>Band Steering: <b>{applyResult.details.bandSteering}</b></div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default WifiEventOptimizer;
