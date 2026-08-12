import React, { useState } from 'react';
import { INITIAL_CHECKLIST } from '../constants';
import { SecurityCheckItem } from '../types';

const Checklist: React.FC = () => {
  const [items, setItems] = useState<SecurityCheckItem[]>(() => {
    const saved = localStorage.getItem('udm_security_checklist');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error("Erro ao carregar checklist do localStorage", e);
      }
    }
    return INITIAL_CHECKLIST;
  });

  const toggleCheck = (id: string) => {
    setItems(prev => {
      const updated = prev.map(item =>
        item.id === id ? { ...item, checked: !item.checked } : item
      );
      localStorage.setItem('udm_security_checklist', JSON.stringify(updated));
      return updated;
    });
  };

  const progress = Math.round((items.filter(i => i.checked).length / items.length) * 100);

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 shadow-lg overflow-hidden">
      <div className="p-6 border-b border-slate-700 bg-slate-900/50">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold text-white">Checklist de Hardening</h2>
          <span className={`text-xl font-bold ${progress === 100 ? 'text-green-500' : 'text-ubiquiti-400'}`}>
            {progress}% Concluído
          </span>
        </div>
        <div className="w-full bg-slate-700 rounded-full h-2.5">
          <div 
            className={`h-2.5 rounded-full transition-all duration-500 ${progress === 100 ? 'bg-green-500' : 'bg-ubiquiti-500'}`} 
            style={{ width: `${progress}%` }}
          ></div>
        </div>
      </div>

      <div className="p-6 space-y-4">
        {items.map((item) => (
          <div 
            key={item.id} 
            className={`flex items-start gap-4 p-4 rounded-lg border transition-all ${
              item.checked 
                ? 'bg-slate-900/30 border-green-900/50' 
                : 'bg-slate-800 border-slate-700 hover:border-slate-600'
            }`}
          >
            <div className="flex-shrink-0 pt-1">
              <input
                type="checkbox"
                checked={item.checked}
                onChange={() => toggleCheck(item.id)}
                className="w-5 h-5 rounded border-slate-500 text-ubiquiti-600 focus:ring-ubiquiti-500 bg-slate-700 cursor-pointer"
              />
            </div>
            <div className="flex-1">
              <div className="flex justify-between items-start">
                <h3 className={`font-semibold text-lg ${item.checked ? 'text-slate-400 line-through' : 'text-white'}`}>
                  {item.title}
                </h3>
                <span className={`text-xs px-2 py-1 rounded font-bold uppercase ${
                  item.criticality === 'high' ? 'bg-red-900/50 text-red-400 border border-red-900' :
                  item.criticality === 'medium' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-900' :
                  'bg-blue-900/50 text-blue-400 border border-blue-900'
                }`}>
                  {item.criticality}
                </span>
              </div>
              <p className={`text-sm mt-1 ${item.checked ? 'text-slate-500' : 'text-slate-300'}`}>
                {item.description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Checklist;