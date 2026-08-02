import React, { useState, useRef, useEffect } from 'react';
import { getSecurityAdvice } from '../services/geminiService';
import { ChatMessage } from '../types';

const SecurityAdvisor: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'model',
      text: 'Olá! Sou seu assistente de segurança para Ubiquiti UDM Pro. Você pode me fazer perguntas ou anexar arquivos de log (ex: resultados do Nmap) para eu analisar.',
      timestamp: Date.now()
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  
  // File upload states
  const [attachedFile, setAttachedFile] = useState<{name: string, content: string} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Basic validation
    if (file.size > 1024 * 1024) { // 1MB limit
      alert('Arquivo muito grande. Por favor, envie arquivos de texto com menos de 1MB.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setAttachedFile({
        name: file.name,
        content: content
      });
    };
    reader.readAsText(file);
    // Reset input value to allow selecting the same file again if needed
    e.target.value = '';
  };

  const removeAttachment = () => {
    setAttachedFile(null);
  };

  const handleSend = async () => {
    if ((!input.trim() && !attachedFile) || loading) return;

    let finalPrompt = input;
    let displayText = input;

    // If there is a file, append it to the prompt and display text
    if (attachedFile) {
      const fileContext = `\n\n--- INÍCIO DO ARQUIVO ANEXADO: ${attachedFile.name} ---\n${attachedFile.content}\n--- FIM DO ARQUIVO ---\n\nPor favor, analise o conteúdo deste arquivo acima com base na minha pergunta: `;
      
      // If input is empty but file exists, provide a default prompt
      if (!input.trim()) {
        finalPrompt = "Analise este arquivo de log/configuração e identifique riscos de segurança." + fileContext;
        displayText = `[Arquivo Anexado: ${attachedFile.name}] Por favor, analise este arquivo.`;
      } else {
        finalPrompt = fileContext + input;
        displayText = `${input}\n\n[Arquivo Anexado: ${attachedFile.name}]`;
      }
    }

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      text: displayText,
      timestamp: Date.now()
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setAttachedFile(null); // Clear attachment after sending
    setLoading(true);

    try {
      const responseText = await getSecurityAdvice(finalPrompt);
      const aiMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: 'model',
        text: responseText,
        timestamp: Date.now()
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (error) {
      console.error(error);
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: 'model',
        text: "Ocorreu um erro ao processar sua solicitação.",
        timestamp: Date.now()
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[600px] bg-slate-800 rounded-lg border border-slate-700 overflow-hidden shadow-xl">
      <div className="bg-slate-900 p-4 border-b border-slate-700 flex justify-between items-center">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
           <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-ubiquiti-500" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
           Consultor IA (Gemini)
        </h2>
        <span className="text-xs text-ubiquiti-400 bg-ubiquiti-900/50 px-2 py-1 rounded">Modelo: Gemini 3 Flash</span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[80%] rounded-lg p-3 text-sm leading-relaxed whitespace-pre-wrap ${
                msg.role === 'user'
                  ? 'bg-ubiquiti-600 text-white rounded-br-none'
                  : 'bg-slate-700 text-slate-200 rounded-bl-none border border-slate-600'
              }`}
            >
              {msg.text}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-700 rounded-lg p-3 rounded-bl-none flex items-center gap-2">
              <div className="w-2 h-2 bg-ubiquiti-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
              <div className="w-2 h-2 bg-ubiquiti-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
              <div className="w-2 h-2 bg-ubiquiti-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Attachment Preview Area */}
      {attachedFile && (
        <div className="px-4 py-2 bg-slate-900 border-t border-slate-700 flex items-center">
          <div className="bg-slate-800 border border-slate-600 text-slate-300 text-xs px-3 py-1.5 rounded-full flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-ubiquiti-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 011.414.586l5.414 5.414a1 1 0 01.586 1.414V19a2 2 0 01-2 2z" />
            </svg>
            <span className="truncate max-w-[200px]">{attachedFile.name}</span>
            <button 
              onClick={removeAttachment}
              className="hover:text-red-400 transition-colors ml-1"
              title="Remover anexo"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>
      )}

      <div className="p-4 bg-slate-900 border-t border-slate-700">
        <div className="flex gap-2 items-end">
          {/* File Input */}
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileSelect}
            className="hidden"
            accept=".txt,.log,.json,.xml,.csv"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="mb-1 text-slate-400 hover:text-ubiquiti-400 p-2 rounded-md hover:bg-slate-800 transition-colors"
            title="Anexar Log ou Arquivo de Texto"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
            </svg>
          </button>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={attachedFile ? "Adicione uma pergunta sobre o arquivo..." : "Digite sua dúvida ou anexe um log (Nmap, Syslog)..."}
            className="flex-1 bg-slate-800 text-white border border-slate-600 rounded-md px-4 py-2 focus:ring-2 focus:ring-ubiquiti-500 focus:outline-none resize-none h-[42px] max-h-[120px] leading-normal"
            style={{ minHeight: '42px' }}
            rows={1}
          />
          <button
            onClick={handleSend}
            disabled={loading || (!input.trim() && !attachedFile)}
            className="mb-0.5 bg-ubiquiti-600 hover:bg-ubiquiti-500 disabled:opacity-50 text-white px-4 py-2 rounded-md font-medium transition-colors flex items-center h-[42px]"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 transform rotate-90" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.894 2.553a1 1 0 00-1.788 0l-7 14a1 1 0 001.169 1.409l5-1.429A1 1 0 009 15.571V11a1 1 0 112 0v4.571a1 1 0 00.725.962l5 1.428a1 1 0 001.17-1.408l-7-14z" />
            </svg>
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-2 text-center">
          Formatos suportados: .txt, .log, .json, .xml. Máx: 1MB.
        </p>
      </div>
    </div>
  );
};

export default SecurityAdvisor;