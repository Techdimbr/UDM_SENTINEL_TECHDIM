import React, { useState } from 'react';
import CommandGenerator from './components/CommandGenerator';
import SecurityAdvisor from './components/SecurityAdvisor';
import Checklist from './components/Checklist';
import UdmLiveIntegration from './components/UdmLiveIntegration';
import ApiCapabilitiesCatalog from './components/ApiCapabilitiesCatalog';
import WhitelabelReportGenerator from './components/WhitelabelReportGenerator';
import WifiEventOptimizer from './components/WifiEventOptimizer';
import NetworkAnalyzer from './components/NetworkAnalyzer';
import { Tab, UDMSystemOverview, UDMDevice, UDMFirewallRule, UDMClient, UDMThreatEvent } from './types';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>(Tab.LIVE_UDM);
  const [agreed, setAgreed] = useState(false);

  // Shared UDM data states to link UdmLiveIntegration and WhitelabelReportGenerator
  const [overview, setOverview] = useState<UDMSystemOverview | null>(null);
  const [devices, setDevices] = useState<UDMDevice[]>([]);
  const [firewallRules, setFirewallRules] = useState<UDMFirewallRule[]>([]);
  const [clients, setClients] = useState<UDMClient[]>([]);
  const [threats, setThreats] = useState<UDMThreatEvent[]>([]);
  const [auditReport, setAuditReport] = useState<string | null>(null);

  if (!agreed) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 font-sans">
        <div className="max-w-md w-full bg-slate-900 border border-red-900/50 rounded-xl p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-red-600 to-orange-600"></div>
          <h1 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
             <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Aviso Legal
          </h1>
          <p className="text-slate-300 mb-6 leading-relaxed">
            Esta ferramenta destina-se <strong>exclusivamente</strong> a fins educacionais e de auditoria autorizada em equipamentos de sua propriedade (Ubiquiti UDM Pro / UDM SE).
          </p>
          <ul className="list-disc list-inside text-slate-400 mb-6 space-y-2 text-sm">
            <li>Não utilize para escanear redes sem permissão explícita.</li>
            <li>Os autores não se responsabilizam por danos ou uso indevido.</li>
            <li>A integração API se comunica via HTTPS seguro com seu console UniFi OS.</li>
          </ul>
          <button
            onClick={() => setAgreed(true)}
            className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded transition-all shadow-lg hover:shadow-red-900/20"
          >
            Concordo e Sou o Proprietário
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-ubiquiti-500 selection:text-white">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-50 backdrop-blur-md bg-opacity-90">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-ubiquiti-500 to-blue-700 rounded flex items-center justify-center text-white font-bold text-xl">U</div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              UDM Pro <span className="text-ubiquiti-400">Sentinel</span>
            </h1>
          </div>
          <nav className="flex flex-wrap gap-1">
            {[
              { id: Tab.LIVE_UDM, label: 'Painel API UDM' },
              { id: Tab.NETWORK_ANALYSIS, label: 'Análise de Rede & Invasão' },
              { id: Tab.EVENT_WIFI, label: 'Wi-Fi Eventos 10k+' },
              { id: Tab.REPORTS, label: 'Relatórios Whitelabel' },
              { id: Tab.CATALOG, label: '50 Recursos API' },
              { id: Tab.GENERATOR, label: 'Auditoria Nmap' },
              { id: Tab.CHECKLIST, label: 'Checklist' },
              { id: Tab.ADVISOR, label: 'Consultor IA' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-ubiquiti-600 text-white shadow-lg shadow-ubiquiti-900/50'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">
            {activeTab === Tab.LIVE_UDM && 'Integração UniFi OS Network API'}
            {activeTab === Tab.NETWORK_ANALYSIS && 'Análise Avançada de Rede, DNS, Exfiltração & Wi-Fi'}
            {activeTab === Tab.EVENT_WIFI && 'Otimização Wi-Fi para Eventos de Alta Densidade (10.000+ Usuários)'}
            {activeTab === Tab.REPORTS && 'Gerador de Relatórios Executivos Whitelabel'}
            {activeTab === Tab.CATALOG && '50 Proteções & Serviços Complementares via API'}
            {activeTab === Tab.GENERATOR && 'Gerador de Testes de Penetração Nmap'}
            {activeTab === Tab.ADVISOR && 'Assistente de Segurança Inteligente IA'}
            {activeTab === Tab.CHECKLIST && 'Lista de Verificação de Hardening'}
          </h2>
          <p className="text-slate-400">
            {activeTab === Tab.LIVE_UDM && 'Monitoramento ao vivo de firewall, equipamentos, clientes e ameaças do seu UDM Pro via API chave.'}
            {activeTab === Tab.NETWORK_ANALYSIS && 'Análise proativa de desvios de DNS, exfiltração contínua de gigabytes, sequestro ARP e ataques contra o espectro Wi-Fi (Deauth).'}
            {activeTab === Tab.EVENT_WIFI && 'Configuração e simulação de parâmetros de RF e WLAN para alta densidade, mitigando interferência de 500+ SSIDs vizinhas.'}
            {activeTab === Tab.REPORTS && 'Gere relatórios executivos personalizados com a logo, nome da sua empresa e pareceres técnicos em PDF, CSV e JSON.'}
            {activeTab === Tab.CATALOG && 'Explore 50 capacidades exclusivas que uma aplicação customizada com acesso à API do UniFi OS pode realizar.'}
            {activeTab === Tab.GENERATOR && 'Crie comandos Nmap personalizados para validar as regras de firewall do seu UDM.'}
            {activeTab === Tab.ADVISOR && 'Tire dúvidas técnicas sobre configurações do UniFi OS com inteligência artificial.'}
            {activeTab === Tab.CHECKLIST && 'Acompanhe as melhores práticas de configuração manual para proteger sua rede.'}
          </p>
        </div>

        <div className="transition-all duration-300">
          {activeTab === Tab.LIVE_UDM && (
            <UdmLiveIntegration
              overview={overview}
              setOverview={setOverview}
              devices={devices}
              setDevices={setDevices}
              firewallRules={firewallRules}
              setFirewallRules={setFirewallRules}
              clients={clients}
              setClients={setClients}
              threats={threats}
              setThreats={setThreats}
              auditReport={auditReport}
              setAuditReport={setAuditReport}
            />
          )}
          {activeTab === Tab.EVENT_WIFI && <WifiEventOptimizer />}
          {activeTab === Tab.REPORTS && (
            <WhitelabelReportGenerator
              overview={overview}
              devices={devices}
              firewallRules={firewallRules}
              threats={threats}
              aiAuditText={auditReport || ''}
            />
          )}
          {activeTab === Tab.CATALOG && <ApiCapabilitiesCatalog />}
          {activeTab === Tab.GENERATOR && <CommandGenerator />}
          {activeTab === Tab.ADVISOR && <SecurityAdvisor />}
          {activeTab === Tab.NETWORK_ANALYSIS && <NetworkAnalyzer />}
          {activeTab === Tab.CHECKLIST && <Checklist />}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 mt-12 py-8 bg-slate-900">
        <div className="max-w-7xl mx-auto px-4 text-center text-slate-500 text-sm">
          <p>© 2026 UDM Pro Sentinel. Ferramenta de código aberto para administradores UniFi OS.</p>
          <p className="mt-2 text-xs">Aviso: Não afiliado à Ubiquiti Inc.</p>
        </div>
      </footer>
    </div>
  );
};

export default App;