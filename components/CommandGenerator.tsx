import React, { useState, useEffect } from 'react';
import { NMAP_OPTIONS } from '../constants';
import { NmapOption } from '../types';
import { getSecurityAdvice } from '../services/geminiService';

const CommandGenerator: React.FC = () => {
  const [ip, setIp] = useState<string>('192.168.1.1');
  const [selectedOptions, setSelectedOptions] = useState<Set<string>>(new Set(['syn', 'timing']));
  const [command, setCommand] = useState<string>('');
  
  // Analysis states
  const [scanResult, setScanResult] = useState('');
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  useEffect(() => {
    const flags = NMAP_OPTIONS
      .filter(opt => selectedOptions.has(opt.id))
      .map(opt => opt.flag)
      .join(' ');
    
    setCommand(`nmap ${flags} ${ip}`);
  }, [ip, selectedOptions]);

  const toggleOption = (id: string) => {
    const newOptions = new Set(selectedOptions);
    if (newOptions.has(id)) {
      newOptions.delete(id);
    } else {
      newOptions.add(id);
    }
    setSelectedOptions(newOptions);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(command);
    alert('Comando copiado para a área de transferência!');
  };

  const handleAnalyze = async () => {
    if (!scanResult.trim()) return;

    setIsAnalyzing(true);
    setAnalysis(null);

    const prompt = `
Contexto: O usuário executou o comando "${command}" em uma auditoria de segurança de um Ubiquiti UDM Pro.
Abaixo está o resultado (output) do scan.
Por favor, aja como um especialista em segurança (Blue Team) e analise este output.
Identifique portas abertas que representam risco, serviços desatualizados se houver, e sugira regras de firewall específicas para mitigar problemas.

Resultado do Scan:
${scanResult}
    `;

    try {
      const result = await getSecurityAdvice(prompt);
      setAnalysis(result);
    } catch (error) {
      console.error("Analysis failed", error);
      setAnalysis("Falha ao conectar com o serviço de análise. Verifique sua conexão ou chave de API.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Generator Section */}
      <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg">
        <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-ubiquiti-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
          Gerador de Comandos Nmap
        </h2>
        <p className="text-slate-400 mb-6">
          Gere comandos seguros para auditar seu UDM Pro externamente ou internamente. 
          <br /><span className="text-yellow-500 text-sm">Nota: Execute estes comandos de uma máquina Linux/WSL na mesma rede ou via VPN.</span>
        </p>

        <div className="mb-6">
          <label className="block text-sm font-medium text-slate-300 mb-2">IP do Alvo (UDM Gateway)</label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            className="w-full bg-slate-900 border border-slate-600 rounded-md py-2 px-4 text-white focus:ring-2 focus:ring-ubiquiti-500 focus:outline-none font-mono"
            placeholder="Ex: 192.168.1.1 ou seu IP Público WAN"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
          {NMAP_OPTIONS.map((opt) => (
            <div 
              key={opt.id}
              onClick={() => toggleOption(opt.id)}
              className={`cursor-pointer p-3 rounded border transition-all ${
                selectedOptions.has(opt.id) 
                  ? 'bg-ubiquiti-900/40 border-ubiquiti-500' 
                  : 'bg-slate-700/30 border-slate-600 hover:bg-slate-700/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-sm font-bold text-ubiquiti-100">{opt.flag}</span>
                {selectedOptions.has(opt.id) && (
                  <span className="h-2 w-2 rounded-full bg-ubiquiti-500"></span>
                )}
              </div>
              <div className="text-sm font-medium text-white">{opt.label}</div>
              <div className="text-xs text-slate-400 mt-1">{opt.description}</div>
            </div>
          ))}
        </div>

        <div className="bg-black rounded-lg p-4 border border-slate-700 relative group mb-6">
          <div className="absolute top-2 left-2 flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <div className="pt-6 overflow-x-auto">
            <code className="text-terminal-text font-mono text-lg block whitespace-nowrap">
              <span className="text-green-400">$</span> {command}
            </code>
          </div>
          <button 
            onClick={copyToClipboard}
            className="absolute top-3 right-3 bg-slate-700 hover:bg-slate-600 text-white text-xs py-1 px-3 rounded transition-colors"
          >
            Copiar
          </button>
        </div>

        {/* Analysis Section */}
        <div className="border-t border-slate-700 pt-6">
          <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-purple-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v2H7a1 1 0 100 2h2v2a1 1 0 102 0v-2h2a1 1 0 100-2h-2V7z" clipRule="evenodd" />
            </svg>
            Análise de Resultados (IA)
          </h3>
          <p className="text-sm text-slate-400 mb-3">
            Cole a saída do terminal abaixo para que a IA identifique riscos e sugira correções.
          </p>
          
          <textarea
            value={scanResult}
            onChange={(e) => setScanResult(e.target.value)}
            className="w-full bg-slate-900 border border-slate-600 rounded-md p-4 text-xs font-mono text-slate-300 focus:ring-2 focus:ring-purple-500 focus:outline-none mb-3"
            rows={6}
            placeholder={`Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-20...
Nmap scan report for 192.168.1.1
Host is up (0.0020s latency).
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
443/tcp  open     https`}
          />
          
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing || !scanResult.trim()}
            className="w-full bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded transition-colors flex justify-center items-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Analisando...
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l-.923 1.537A1.18 1.18 0 0110.9 18H9.1a1.18 1.18 0 01-1.027-1.537L7.22 15H5a2 2 0 01-2-2V5zm5.771 7H5V5h10v7H8.771z" clipRule="evenodd" />
                </svg>
                Analisar Saída do Scan
              </>
            )}
          </button>

          {/* Analysis Result */}
          {analysis && (
            <div className="mt-6 bg-slate-900/50 rounded-lg p-4 border border-purple-500/30">
              <h4 className="text-purple-400 font-bold mb-2 text-sm uppercase tracking-wider">Relatório de Análise</h4>
              <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
                {analysis}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
        <h3 className="text-xl font-bold text-white mb-2">Instruções de Uso</h3>
        <ol className="list-decimal list-inside text-slate-300 space-y-2">
          <li>Instale o <strong>Nmap</strong> em sua máquina de auditoria (Kali Linux, Ubuntu, macOS ou Windows).</li>
          <li>Copie o comando gerado acima.</li>
          <li>Abra seu terminal ou PowerShell.</li>
          <li>Cole o comando e pressione Enter.</li>
          <li>Copie todo o texto retornado pelo comando no terminal.</li>
          <li>Cole no campo de análise acima e clique em "Analisar Saída do Scan".</li>
        </ol>
      </div>
    </div>
  );
};

export default CommandGenerator;