// Using global window.vulnerabilities loaded via script tag in index.html

function App() {
  const [selectedVuln, setSelectedVuln] = React.useState(vulnerabilities[0]);
  const [searchQuery, setSearchQuery] = React.useState('');
  const [activeTab, setActiveTab] = React.useState('overview'); // overview, code, simulation
  const [simStep, setSimStep] = React.useState(0);
  const [showSecureSim, setShowSecureSim] = React.useState(false);

  // Initialize Lucide Icons after mount and updates
  React.useEffect(() => {
    if (window.lucide) {
      window.lucide.createIcons();
    }
  }, [selectedVuln, activeTab, showSecureSim, simStep]);

  const filteredVulns = vulnerabilities.filter(v => 
    v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelectVuln = (vuln) => {
    setSelectedVuln(vuln);
    setActiveTab('overview');
    setSimStep(0);
    setShowSecureSim(false);
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case 'High': return 'bg-brand-dangerBg text-red-400 border-red-900/50';
      case 'Medium': return 'bg-brand-warningBg text-amber-400 border-amber-900/50';
      case 'Low': return 'bg-emerald-950/40 text-emerald-400 border-emerald-900/50';
      default: return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="min-h-screen bg-brand-dark bg-grid flex flex-col">
      {/* Top Banner & Header */}
      <header className="border-b border-slate-800/80 bg-brand-dark/95 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <i data-lucide="shield-alert" className="text-white w-6 h-6"></i>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                OWASP API <span className="text-blue-500 font-semibold">Top 10</span> (2023)
              </h1>
              <p className="text-xs text-slate-400">Interactive PoC & Remediation Dashboard</p>
            </div>
          </div>
          
          {/* Search bar */}
          <div className="relative w-full sm:w-80">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              <i data-lucide="search" className="h-5 w-5 text-slate-500"></i>
            </span>
            <input
              type="text"
              className="w-full bg-slate-900/80 border border-slate-800 rounded-xl pl-10 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              placeholder="Search vulnerabilities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </header>

      {/* Main Layout */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Sidebar list (4 cols) */}
        <aside className="lg:col-span-4 flex flex-col gap-4">
          <h2 className="text-sm font-semibold tracking-wider text-slate-500 uppercase px-2">Vulnerabilities</h2>
          <div className="space-y-2 overflow-y-auto max-h-[calc(100vh-220px)] pr-2">
            {filteredVulns.map((vuln) => (
              <button
                key={vuln.id}
                onClick={() => handleSelectVuln(vuln)}
                className={`w-full text-left p-4 rounded-xl border transition-all duration-200 flex flex-col gap-2 ${
                  selectedVuln.id === vuln.id
                    ? 'bg-blue-600/10 border-blue-500/50 shadow-md shadow-blue-500/5'
                    : 'bg-brand-card/40 hover:bg-brand-card/70 border-slate-800/80'
                }`}
              >
                <div className="flex items-center justify-between w-full">
                  <span className="font-mono text-xs font-semibold text-blue-400">{vuln.id}</span>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${getSeverityBadgeClass(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                </div>
                <h3 className="font-semibold text-sm text-slate-200 leading-tight line-clamp-1">{vuln.title.split(': ')[1] || vuln.title}</h3>
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">{vuln.description}</p>
              </button>
            ))}
            {filteredVulns.length === 0 && (
              <div className="text-center py-8 text-slate-500 text-sm">
                No vulnerabilities match your search.
              </div>
            )}
          </div>
        </aside>

        {/* Content Panel (8 cols) */}
        <main className="lg:col-span-8 flex flex-col gap-6 animate-fade-in">
          
          {/* Header Card */}
          <div className="glass-card rounded-2xl p-6 flex flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/60 pb-4">
              <div>
                <span className="font-mono text-sm text-blue-500 font-medium">{selectedVuln.id} classification</span>
                <h2 className="text-2xl font-bold text-white mt-1">{selectedVuln.title}</h2>
              </div>
              <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${getSeverityBadgeClass(selectedVuln.severity)}`}>
                {selectedVuln.severity} Severity
              </span>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800/60 -mx-6 px-6">
              {[
                { id: 'overview', label: 'Overview', icon: 'book-open' },
                { id: 'code', label: 'Code Comparison', icon: 'code-2' },
                { id: 'simulation', label: 'Logic Simulation', icon: 'play' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 py-3 px-4 border-b-2 text-sm font-medium transition-all ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <i data-lucide={tab.icon} className="w-4 h-4"></i>
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div className="pt-2">
              
              {/* OVERVIEW TAB */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Vulnerability Concept</h3>
                    <p className="text-slate-300 text-sm leading-relaxed">{selectedVuln.concept}</p>
                  </div>

                  <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
                    <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                      <i data-lucide="shield-check" className="w-4 h-4 text-emerald-500"></i>
                      Defensive Remediation Checklist
                    </h3>
                    <ul className="space-y-2.5">
                      {selectedVuln.remediation.map((item, idx) => (
                        <li key={idx} className="flex gap-2.5 text-xs text-slate-400 items-start">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0"></span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* CODE TAB */}
              {activeTab === 'code' && (
                <div className="space-y-6">
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Compare the differences in structural design patterns. See how neglecting input controls introduces vulnerabilities, and how defensive design patterns close the gap.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Vulnerable Code Card */}
                    <div className="flex flex-col border border-red-950/60 bg-red-950/10 rounded-xl overflow-hidden">
                      <div className="bg-brand-dangerBg/50 border-b border-red-950/60 px-4 py-2 flex items-center gap-2">
                        <i data-lucide="x-circle" className="text-red-400 w-4 h-4"></i>
                        <span className="text-xs font-semibold text-red-400 font-mono">Vulnerable Logic</span>
                      </div>
                      <pre className="p-4 text-xs font-mono overflow-x-auto text-red-200/90 whitespace-pre-wrap select-all leading-relaxed bg-black/35 flex-1">
                        {selectedVuln.vulnerableCode}
                      </pre>
                    </div>

                    {/* Secure Code Card */}
                    <div className="flex flex-col border border-emerald-950/60 bg-emerald-950/10 rounded-xl overflow-hidden">
                      <div className="bg-brand-safeBg/50 border-b border-emerald-950/60 px-4 py-2 flex items-center gap-2">
                        <i data-lucide="check-circle-2" className="text-emerald-400 w-4 h-4"></i>
                        <span className="text-xs font-semibold text-emerald-400 font-mono">Mitigated Logic</span>
                      </div>
                      <pre className="p-4 text-xs font-mono overflow-x-auto text-emerald-200/90 whitespace-pre-wrap select-all leading-relaxed bg-black/35 flex-1">
                        {selectedVuln.secureCode}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* SIMULATION TAB */}
              {activeTab === 'simulation' && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between flex-wrap gap-3 bg-slate-900/60 border border-slate-800/80 px-4 py-3 rounded-xl">
                    <div>
                      <h4 className="text-sm font-semibold text-slate-300">{selectedVuln.simulation.title}</h4>
                      <p className="text-xs text-slate-400">Step-by-step logic tracing</p>
                    </div>
                    
                    {/* Toggle Secure/Vulnerable Simulation */}
                    <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
                      <button
                        onClick={() => { setShowSecureSim(false); setSimStep(0); }}
                        className={`text-xs px-3 py-1.5 rounded-md font-medium transition-all ${
                          !showSecureSim 
                            ? 'bg-red-500/20 text-red-400 border border-red-900/30' 
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Vulnerable State
                      </button>
                      <button
                        onClick={() => { setShowSecureSim(true); setSimStep(0); }}
                        className={`text-xs px-3 py-1.5 rounded-md font-medium transition-all ${
                          showSecureSim 
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-900/30' 
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Mitigated State
                      </button>
                    </div>
                  </div>

                  {/* Flow Simulation Stepper */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-stretch">
                    
                    {/* Progress indicators */}
                    <div className="md:col-span-4 flex md:flex-col gap-2 overflow-x-auto md:overflow-x-visible pb-2 md:pb-0">
                      {selectedVuln.simulation.steps.map((step, idx) => (
                        <button
                          key={idx}
                          onClick={() => setSimStep(idx)}
                          className={`flex items-center gap-3 text-left p-3 rounded-xl border transition-all w-full min-w-[140px] md:min-w-0 ${
                            simStep === idx
                              ? showSecureSim
                                ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                                : 'bg-red-500/10 border-red-500/40 text-red-400'
                              : 'bg-slate-900/20 hover:bg-slate-900/40 border-slate-800/60 text-slate-400'
                          }`}
                        >
                          <span className={`w-6 h-6 rounded-full flex items-center justify-center font-mono text-xs border ${
                            simStep === idx
                              ? showSecureSim
                                ? 'border-emerald-500/50 bg-emerald-950/50'
                                : 'border-red-500/50 bg-red-950/50'
                              : 'border-slate-800 bg-slate-900'
                          }`}>
                            {idx + 1}
                          </span>
                          <span className="text-xs font-medium hidden sm:inline">{step.label}</span>
                        </button>
                      ))}
                    </div>

                    {/* Step Details View */}
                    <div className={`md:col-span-8 flex flex-col justify-between border rounded-2xl p-6 glass-card transition-all ${
                      showSecureSim 
                        ? 'border-emerald-950/60 bg-emerald-950/5' 
                        : 'border-red-950/60 bg-red-950/5'
                    }`}>
                      <div>
                        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
                          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            STEP {simStep + 1}: {selectedVuln.simulation.steps[simStep].label}
                          </span>
                          <i data-lucide={showSecureSim ? "shield" : "skull"} className={`w-5 h-5 ${
                            showSecureSim ? "text-emerald-500" : "text-red-500"
                          }`}></i>
                        </div>
                        
                        <p className="text-slate-300 text-sm leading-relaxed mb-6">
                          {selectedVuln.simulation.steps[simStep].description}
                        </p>
                      </div>

                      <div className={`p-4 rounded-xl border ${
                        showSecureSim 
                          ? 'bg-emerald-950/20 border-emerald-900/50' 
                          : 'bg-red-950/20 border-red-900/50'
                      }`}>
                        <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 block mb-1">
                          Logic Controller State
                        </span>
                        <p className={`text-xs font-mono font-medium ${
                          showSecureSim ? 'text-emerald-400' : 'text-red-400'
                        }`}>
                          {showSecureSim 
                            ? selectedVuln.simulation.steps[simStep].secureStatus 
                            : selectedVuln.simulation.steps[simStep].vulnerableStatus
                          }
                        </p>
                      </div>

                      {/* Navigation buttons inside card */}
                      <div className="flex justify-between items-center mt-6 border-t border-slate-800/60 pt-4">
                        <button
                          disabled={simStep === 0}
                          onClick={() => setSimStep(prev => prev - 1)}
                          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                        >
                          <i data-lucide="chevron-left" className="w-4 h-4"></i> Back
                        </button>
                        
                        <button
                          disabled={simStep === selectedVuln.simulation.steps.length - 1}
                          onClick={() => setSimStep(prev => prev + 1)}
                          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                        >
                          Next <i data-lucide="chevron-right" className="w-4 h-4"></i>
                        </button>
                      </div>
                    </div>

                  </div>
                </div>
              )}

            </div>
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-900/80 bg-brand-dark/40 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 text-center text-xs text-slate-500">
          OWASP® API Security Top 10 (2023) is a registered trademark of the OWASP Foundation. This dashboard is for educational and training purposes.
        </div>
      </footer>
    </div>
  );
}

// Mount the application to the root container
const container = document.getElementById('root');
const root = ReactDOM.createRoot(container);
root.render(<App />);

