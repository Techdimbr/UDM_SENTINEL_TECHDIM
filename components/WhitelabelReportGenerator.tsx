import React, { useState } from 'react';
import { WhitelabelConfig, UDMSystemOverview, UDMDevice, UDMFirewallRule, UDMThreatEvent } from '../types';
import { 
  FileText, Download, Printer, Shield, CheckCircle2, AlertTriangle, 
  Building, User, Image, Sparkles, Sliders, Database, Eye, RefreshCw, ChevronRight, Lock
} from 'lucide-react';

interface Props {
  overview?: UDMSystemOverview | null;
  devices?: UDMDevice[];
  firewallRules?: UDMFirewallRule[];
  threats?: UDMThreatEvent[];
  aiAuditText?: string;
}

const WhitelabelReportGenerator: React.FC<Props> = ({
  overview,
  devices = [],
  firewallRules = [],
  threats = [],
  aiAuditText = ''
}) => {
  const [config, setConfig] = useState<WhitelabelConfig>({
    companyName: 'Sentinel Security MSP',
    companyLogoUrl: 'https://images.unsplash.com/photo-1563986768609-322da13575f3?w=120&auto=format&fit=crop&q=80',
    auditorName: 'Eng. Ricardo Silva',
    auditorTitle: 'Especialista Sênior em Cibersegurança & Redes',
    clientName: 'Grupo Empresarial Santos & Filhos',
    reportTitle: 'Relatório Executivo de Auditoria & Hardening UDM Pro',
    customNotes: 'A infraestrutura do UniFi Dream Machine Pro foi submetida a análises minuciosas de política de firewall, vetores de ataque em portas WAN e conformidade com políticas Zero Trust. As recomendações deste relatório visam blindar o ambiente corporativo.',
    includeAiAudit: true,
    includeFirewallRules: true,
    includeDeviceInventory: true,
    includeThreatLog: true,
    includeWifiEventConfig: true,
  });

  const [activeView, setActiveView] = useState<'EDIT' | 'PREVIEW'>('PREVIEW');
  const [exporting, setExporting] = useState(false);

  // Default simulated data if props empty
  const currentOverview = overview || {
    name: 'UDM Pro Primary Gateway',
    model: 'UniFi Dream Machine Pro',
    version: '4.0.6',
    unifiOsVersion: '4.0.6',
    uptime: 1245600,
    cpuUsage: 18.4,
    memoryUsage: 42.1,
    storageUsage: 28.5,
    wanIp: '187.58.120.44',
    wanStatus: 'CONNECTED',
    gatewayIp: '192.168.1.1',
    isp: 'Claro Brasil / AS28573',
    latencyMs: 12,
    connectedClientsCount: 24,
    adoptedDevicesCount: 5,
    activeThreatsCount: 3
  };

  const currentAuditText = aiAuditText || `
### Resumo Executivo da Auditoria de Segurança
O gateway **UniFi Dream Machine Pro** opera com a versão de firmware **4.0.6** e apresenta postura de segurança **SATISFATÓRIA (Pontuação: 88/100)**.

#### Pontos Fortes Observados:
1. **Isolamento de VLANs Críticas**: A regra LAN_IN 3001 bloqueia com sucesso o tráfego da VLAN de IoT (192.168.30.0/24) para a rede corporativa.
2. **Motor IPS/IDS Ativo**: Foram registrados e mitigados 3 bloqueios automáticos de tentativas de exploração externa na porta 22 (SSH) e exfiltração de dados em IPs maliciosos.

#### Recomendações de Ação Imediata:
- **Restrição de Acesso SSH**: Restringir o acesso administrativo de SSH apenas aos IPs locais da equipe de TI (192.168.1.50).
- **Hardening da WAN**: Desativar resposta a PING ICMP na interface WAN1 pública para diminuir a visibilidade do gateway contra port scanners automatizados.
  `;

  // Export CSV
  const handleExportCSV = () => {
    setExporting(true);
    let csvContent = `data:text/csv;charset=utf-8,`;
    
    // Header
    csvContent += `RELATÓRIO AUDITORIA UDM PRO - ${config.companyName}\n`;
    csvContent += `Cliente: ${config.clientName}\n`;
    csvContent += `Auditor: ${config.auditorName} (${config.auditorTitle})\n`;
    csvContent += `Data: ${new Date().toLocaleDateString('pt-BR')}\n\n`;

    // System Overview
    csvContent += `--- VISÃO GERAL DO GATEWAY ---\n`;
    csvContent += `Gateway,Modelo,Versão UniFi OS,IP WAN,Status WAN,Clientes,Dispositivos,Ameaças\n`;
    csvContent += `"${currentOverview.name}","${currentOverview.model}","${currentOverview.unifiOsVersion}","${currentOverview.wanIp}","${currentOverview.wanStatus}",${currentOverview.connectedClientsCount},${currentOverview.adoptedDevicesCount},${currentOverview.activeThreatsCount}\n\n`;

    // Firewall Rules
    if (config.includeFirewallRules && firewallRules.length > 0) {
      csvContent += `--- REGRAS DE FIREWALL ---\n`;
      csvContent += `ID,Ruleset,Ordem,Ação,Protocolo,Nome,Status,Origem,Destino,Porta Destino\n`;
      firewallRules.forEach(r => {
        csvContent += `"${r.id}","${r.ruleset}",${r.ruleIndex},"${r.action}","${r.protocol}","${r.name}","${r.enabled ? 'ATIVO' : 'INATIVO'}","${r.srcAddress || '*'}","${r.dstAddress || '*'}","${r.dstPort || '*'}"\n`;
      });
      csvContent += `\n`;
    }

    // Devices
    if (config.includeDeviceInventory && devices.length > 0) {
      csvContent += `--- INVENTÁRIO DE DISPOSITIVOS ---\n`;
      csvContent += `ID,Nome,Modelo,IP,MAC,Status,Tipo,Firmware\n`;
      devices.forEach(d => {
        csvContent += `"${d.id}","${d.name}","${d.model}","${d.ip}","${d.mac}","${d.status}","${d.type}","${d.firmware}"\n`;
      });
      csvContent += `\n`;
    }

    // Threats
    if (config.includeThreatLog && threats.length > 0) {
      csvContent += `--- HISTÓRICO DE AMEAÇAS IPS/IDS ---\n`;
      csvContent += `ID,Data/Hora,Severidade,Categoria,Origem,Destino,Porta,Ação,Assinatura\n`;
      threats.forEach(t => {
        csvContent += `"${t.id}","${t.timestamp}","${t.severity}","${t.category}","${t.srcIp}","${t.dstIp}",${t.dstPort},"${t.actionTaken}","${t.signature.replace(/"/g, '""')}"\n`;
      });
    }

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `Relatorio_UDMPro_${config.clientName.replace(/\s+/g, '_')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setExporting(false);
  };

  // Export JSON
  const handleExportJSON = () => {
    const reportData = {
      metadata: {
        companyName: config.companyName,
        auditor: config.auditorName,
        auditorTitle: config.auditorTitle,
        client: config.clientName,
        generatedAt: new Date().toISOString(),
        title: config.reportTitle,
      },
      gatewayOverview: currentOverview,
      aiAuditSummary: currentAuditText,
      firewallRules: config.includeFirewallRules ? firewallRules : [],
      deviceInventory: config.includeDeviceInventory ? devices : [],
      threatsHistory: config.includeThreatLog ? threats : [],
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `Relatorio_UDMPro_${config.clientName.replace(/\s+/g, '_')}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Trigger browser print for PDF export
  const handlePrintPDF = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-900/50 text-blue-300 border border-blue-700/50 text-xs font-semibold uppercase tracking-wider mb-2">
            <Building className="w-3.5 h-3.5" /> Módulo Whitelabel MSP
          </div>
          <h2 className="text-2xl font-extrabold text-white">
            Gerador de Relatórios Executivos com Sua Marca
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Exporte relatórios formais de cibersegurança e saúde de rede do UDM Pro em PDF, CSV e JSON personalizados para entregar a seus clientes.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
          <button
            onClick={() => setActiveView(activeView === 'EDIT' ? 'PREVIEW' : 'EDIT')}
            className={`px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 border transition-all ${
              activeView === 'EDIT'
                ? 'bg-ubiquiti-600 border-ubiquiti-500 text-white shadow-lg'
                : 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Sliders className="w-4 h-4" /> {activeView === 'EDIT' ? 'Visualizar Documento' : 'Editar Dados & Logotipo'}
          </button>

          <button
            onClick={handlePrintPDF}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm flex items-center gap-2 shadow-lg shadow-emerald-950/40 transition-all"
          >
            <Printer className="w-4 h-4" /> Imprimir / PDF
          </button>

          <button
            onClick={handleExportCSV}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold text-sm flex items-center gap-2 transition-all"
          >
            <Download className="w-4 h-4 text-emerald-400" /> Exportar CSV
          </button>

          <button
            onClick={handleExportJSON}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold text-sm flex items-center gap-2 transition-all"
          >
            <Database className="w-4 h-4 text-ubiquiti-400" /> JSON
          </button>
        </div>
      </div>

      {/* Editor Form View */}
      {activeView === 'EDIT' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
          <h3 className="text-lg font-bold text-white border-b border-slate-800 pb-3 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-ubiquiti-400" /> Personalização da Identidade Whitelabel
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Nome da Sua Empresa (MSP / Consultoria)
              </label>
              <input
                type="text"
                value={config.companyName}
                onChange={(e) => setConfig({ ...config, companyName: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Nome do Cliente Final
              </label>
              <input
                type="text"
                value={config.clientName}
                onChange={(e) => setConfig({ ...config, clientName: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Nome do Auditor / Responsável Técnico
              </label>
              <input
                type="text"
                value={config.auditorName}
                onChange={(e) => setConfig({ ...config, auditorName: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Cargo / Certificação do Auditor
              </label>
              <input
                type="text"
                value={config.auditorTitle}
                onChange={(e) => setConfig({ ...config, auditorTitle: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Título do Relatório
              </label>
              <input
                type="text"
                value={config.reportTitle}
                onChange={(e) => setConfig({ ...config, reportTitle: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 font-bold"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                Notas do Especialista & Contexto do Cliente
              </label>
              <textarea
                rows={3}
                value={config.customNotes}
                onChange={(e) => setConfig({ ...config, customNotes: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-sm text-white focus:outline-none focus:border-ubiquiti-500 leading-relaxed"
              />
            </div>
          </div>

          <div className="border-t border-slate-800 pt-5">
            <h4 className="text-sm font-bold text-white mb-3">Seções Incluídas no Relatório</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
              <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.includeAiAudit}
                  onChange={(e) => setConfig({ ...config, includeAiAudit: e.target.checked })}
                  className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
                />
                <span className="text-xs font-semibold text-slate-200">Resumo Inteligente IA</span>
              </label>

              <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.includeFirewallRules}
                  onChange={(e) => setConfig({ ...config, includeFirewallRules: e.target.checked })}
                  className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
                />
                <span className="text-xs font-semibold text-slate-200">Regras de Firewall</span>
              </label>

              <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.includeDeviceInventory}
                  onChange={(e) => setConfig({ ...config, includeDeviceInventory: e.target.checked })}
                  className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
                />
                <span className="text-xs font-semibold text-slate-200">Inventário de Ativos</span>
              </label>

              <label className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.includeThreatLog}
                  onChange={(e) => setConfig({ ...config, includeThreatLog: e.target.checked })}
                  className="rounded bg-slate-800 border-slate-700 text-ubiquiti-500 focus:ring-0"
                />
                <span className="text-xs font-semibold text-slate-200">Log de Ameaças IPS</span>
              </label>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={() => setActiveView('PREVIEW')}
              className="bg-ubiquiti-600 hover:bg-ubiquiti-500 text-white font-semibold text-sm px-6 py-2.5 rounded-lg transition-all"
            >
              Concluir Edição & Visualizar Documento
            </button>
          </div>
        </div>
      )}

      {/* DOCUMENT PREVIEW (PRINTABLE STYLED REPORT) */}
      <div className="bg-slate-950 p-2 sm:p-6 rounded-xl border border-slate-800 shadow-2xl overflow-x-auto">
        <div 
          id="printable-report"
          className="bg-white text-slate-900 font-sans p-8 sm:p-12 rounded-lg max-w-4xl mx-auto shadow-2xl space-y-8 text-sm"
        >
          {/* Header Whitelabel */}
          <div className="border-b-2 border-slate-900 pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <span className="text-xs font-extrabold tracking-widest text-ubiquiti-600 uppercase block mb-1">
                {config.companyName}
              </span>
              <h1 className="text-2xl sm:text-3xl font-black text-slate-900 leading-tight">
                {config.reportTitle}
              </h1>
              <p className="text-xs text-slate-500 mt-1">
                Gerado em {new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' })} • Emissão de Auditoria Técnica
              </p>
            </div>

            <div className="text-left sm:text-right bg-slate-50 p-3 rounded border border-slate-200">
              <span className="text-[10px] font-bold text-slate-400 uppercase block">Cliente Final</span>
              <span className="font-bold text-slate-900 text-base">{config.clientName}</span>
            </div>
          </div>

          {/* Context Notes */}
          {config.customNotes && (
            <div className="bg-slate-50 border-l-4 border-slate-900 p-4 rounded-r text-xs leading-relaxed text-slate-700 italic">
              "{config.customNotes}"
            </div>
          )}

          {/* Executive Summary Cards */}
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3 border-b border-slate-200 pb-1">
              1. Visão Geral da Infraestrutura UDM Pro
            </h2>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
              <div className="bg-slate-100 p-3 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Gateway</span>
                <span className="font-black text-slate-900 text-sm block truncate">{currentOverview.name}</span>
                <span className="text-[10px] text-slate-600 font-mono">{currentOverview.gatewayIp}</span>
              </div>

              <div className="bg-slate-100 p-3 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Firmware</span>
                <span className="font-black text-slate-900 text-sm block">UniFi OS {currentOverview.unifiOsVersion}</span>
                <span className="text-[10px] text-slate-600 font-mono">Build Estável</span>
              </div>

              <div className="bg-slate-100 p-3 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Status WAN</span>
                <span className="font-black text-emerald-700 text-sm block">CONECTADO</span>
                <span className="text-[10px] text-slate-600 font-mono">{currentOverview.wanIp}</span>
              </div>

              <div className="bg-slate-100 p-3 rounded border border-slate-200">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Ameaças Mitigadas</span>
                <span className="font-black text-red-600 text-sm block">{currentOverview.activeThreatsCount} Eventos</span>
                <span className="text-[10px] text-slate-600 font-mono">IPS/IDS Suricata</span>
              </div>
            </div>
          </div>

          {/* AI Security Assessment */}
          {config.includeAiAudit && (
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3 border-b border-slate-200 pb-1 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-ubiquiti-600" /> 2. Parecer Técnico & Recomendações
              </h2>

              <div className="bg-slate-50 border border-slate-200 p-4 rounded text-xs leading-relaxed text-slate-800 whitespace-pre-line font-mono">
                {currentAuditText}
              </div>
            </div>
          )}

          {/* Firewall Rules Section */}
          {config.includeFirewallRules && firewallRules.length > 0 && (
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3 border-b border-slate-200 pb-1">
                3. Matriz de Firewall e Políticas de Acesso
              </h2>

              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b-2 border-slate-300 bg-slate-100 text-slate-700">
                    <th className="p-2 font-bold">Ruleset</th>
                    <th className="p-2 font-bold">Ação</th>
                    <th className="p-2 font-bold">Nome da Regra</th>
                    <th className="p-2 font-bold">Origem</th>
                    <th className="p-2 font-bold">Destino</th>
                    <th className="p-2 font-bold">Porta</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {firewallRules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-50 font-mono text-[11px]">
                      <td className="p-2 font-bold">{rule.ruleset}</td>
                      <td className="p-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          rule.action === 'DROP' ? 'bg-red-100 text-red-800' : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                      <td className="p-2 font-sans font-medium">{rule.name}</td>
                      <td className="p-2">{rule.srcAddress || '*'}</td>
                      <td className="p-2">{rule.dstAddress || '*'}</td>
                      <td className="p-2">{rule.dstPort || '*'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Threat Log Section */}
          {config.includeThreatLog && threats.length > 0 && (
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3 border-b border-slate-200 pb-1">
                4. Registro Recente de Intrusões & Ameaças Bloqueadas (IPS)
              </h2>

              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b-2 border-slate-300 bg-slate-100 text-slate-700">
                    <th className="p-2 font-bold">Data</th>
                    <th className="p-2 font-bold">Severidade</th>
                    <th className="p-2 font-bold">Categoria</th>
                    <th className="p-2 font-bold">IP Origem</th>
                    <th className="p-2 font-bold">Ação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {threats.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-50 font-mono text-[11px]">
                      <td className="p-2">{new Date(t.timestamp).toLocaleDateString('pt-BR')}</td>
                      <td className="p-2 font-bold text-red-700">{t.severity}</td>
                      <td className="p-2 font-sans">{t.category}</td>
                      <td className="p-2 font-bold">{t.srcIp}</td>
                      <td className="p-2">
                        <span className="px-1 py-0.5 bg-slate-200 rounded text-[10px] font-bold">
                          {t.actionTaken}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Signatures Footer */}
          <div className="border-t-2 border-slate-300 pt-8 mt-12 grid grid-cols-2 gap-8">
            <div className="text-center border-t border-slate-400 pt-2">
              <span className="font-bold text-slate-900 block">{config.auditorName}</span>
              <span className="text-xs text-slate-500 block">{config.auditorTitle}</span>
              <span className="text-[10px] text-slate-400 block mt-1">{config.companyName}</span>
            </div>

            <div className="text-center border-t border-slate-400 pt-2">
              <span className="font-bold text-slate-900 block">Aprovação do Cliente</span>
              <span className="text-xs text-slate-500 block">{config.clientName}</span>
              <span className="text-[10px] text-slate-400 block mt-1">Carimbo e Assinatura</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WhitelabelReportGenerator;
