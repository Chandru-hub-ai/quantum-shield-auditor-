/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { GoogleGenAI, Type } from "@google/genai";
import { 
  ShieldAlert, 
  ShieldCheck, 
  Code2, 
  Terminal, 
  AlertTriangle, 
  Zap, 
  Info, 
  Copy, 
  CheckCircle2, 
  RefreshCw,
  Search,
  Cpu,
  History,
  Clock,
  ChevronRight,
  Atom,
  Lock,
  Unlock,
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  LayoutDashboard,
  Eye,
  EyeOff,
  Sparkles,
  Sun,
  Moon,
  Download,
  Save,
  Check,
  Trash2,
  FileCode,
  ClipboardCheck,
  ArrowRight,
  Plus
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { DiffEditor } from '@monaco-editor/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- Types ---
interface Change {
  line: number;
  issue: string;
  fix: string;
  severity: string;
}

interface AuditResponse {
  original_code: string;
  fixed_code: string;
  changes_made: Change[];
  summary: string;
  test_script?: string;
  test_result?: string;
}

interface ScanHistoryItem {
  id: number;
  original_code: string;
  fixed_code: string;
  summary: string;
  issue_count: number;
  changes_json: string;
  test_script?: string;
  test_result?: string;
  created_at: string;
}

// --- Utility ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Constants ---
const DEFAULT_CODE = `// Vulnerable Code Example
const crypto = require('crypto');

function hashPassword(password) {
  // ⚠️ MD5 is legacy and quantum-vulnerable
  return crypto.createHash('md5').update(password).digest('hex');
}

function connectToDB(user, pass) {
  // ⚠️ SQL Injection risk
  const query = "SELECT * FROM users WHERE user = '" + user + "' AND pass = '" + pass + "'";
  db.execute(query);
}

// ⚠️ Legacy RSA Encryption - Not Quantum Resistant
const rsa_key = '-----BEGIN RSA PRIVATE KEY-----...'; 
`;

const SYSTEM_INSTRUCTION = `Identify all OWASP and Quantum vulnerabilities (RSA, ECC, AES-128, etc) in the provided code.

Refactor the code into a fixed_code version that is secure and uses PQC (Post-Quantum Cryptography) where applicable (e.g., Kyber, Dilithium, or high-bit AES).

Verify your fix: Use the Code Execution Tool to write and run a test script. The test must confirm that the vulnerability is gone and the logic still works.

Return a JSON object ONLY with the following structure:
{
  "original_code": "...",
  "fixed_code": "...",
  "test_script": "The Python test script used for verification",
  "test_result": "passed/failed",
  "changes_made": [{"line": 10, "issue": "RSA detected", "fix": "Upgraded to Kyber-768", "severity": "Critical"}],
  "summary": "Brief overview of the security session"
}`;

const RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    original_code: { type: Type.STRING },
    fixed_code: { type: Type.STRING },
    test_script: { type: Type.STRING },
    test_result: { type: Type.STRING },
    changes_made: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          line: { type: Type.INTEGER },
          issue: { type: Type.STRING },
          fix: { type: Type.STRING },
          severity: { type: Type.STRING },
        },
        required: ["line", "issue", "fix", "severity"],
      },
    },
    summary: { type: Type.STRING },
  },
  required: ["original_code", "fixed_code", "test_script", "test_result", "changes_made", "summary"],
};

export default function App() {
  const [originalCode, setOriginalCode] = useState(DEFAULT_CODE);
  const [fixedCode, setFixedCode] = useState(DEFAULT_CODE);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AuditResponse | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(true);
  const [showDashboard, setShowDashboard] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "fixes">("date");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [isSaving, setIsSaving] = useState(false);
  const [isClearing, setIsClearing] = useState(false);
  const [viewMode, setViewMode] = useState<"editor" | "report">("editor");
  const [saveStatus, setSaveStatus] = useState<"idle" | "success" | "error">("idle");

  const fetchHistory = useCallback(async () => {
    try {
      const response = await fetch("/api/history");
      if (response.ok) {
        const data = await response.json();
        setHistory(data);
      }
    } catch (err) {
      console.error("Shield history offline:", err);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const filteredHistory = history
    .filter(item => 
      (item.summary || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.original_code || "").toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      if (sortBy === "date") {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      }
      return b.issue_count - a.issue_count;
    });

  const saveScan = async (data: Partial<AuditResponse> & { fixed_code: string, original_code?: string }) => {
    console.log("Attempting to save scan to history...", { summary: data.summary });
    setIsSaving(true);
    setSaveStatus("idle");
    try {
      const payload = {
        original_code: data.original_code || originalCode,
        fixed_code: data.fixed_code,
        summary: data.summary || "Manual Snapshot",
        issue_count: data.changes_made?.length || 0,
        changes_json: JSON.stringify(data.changes_made || []),
        test_script: data.test_script || null,
        test_result: data.test_result || null
      };

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        console.log("Scan saved successfully");
        setSaveStatus("success");
        setTimeout(() => setSaveStatus("idle"), 3000);
        await fetchHistory();
      } else {
        const errData = await response.json();
        console.error("Server rejected scan save:", errData);
        setSaveStatus("error");
      }
    } catch (err) {
      console.error("Network error while saving scan:", err);
      setSaveStatus("error");
    } finally {
      setIsSaving(false);
    }
  };

  const initiateShieldScan = async () => {
    if (!originalCode.trim()) return;
    
    setIsAnalyzing(true);
    setError(null);
    
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: originalCode,
        config: {
          systemInstruction: SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          responseSchema: RESPONSE_SCHEMA,
          tools: [{ codeExecution: {} }]
        },
      });

      const data = JSON.parse(response.text || "{}") as AuditResponse;
      setResults(data);
      setFixedCode(data.fixed_code);
      // Pass the current originalCode explicitly to ensure it's saved correctly
      await saveScan({ ...data, original_code: originalCode });
    } catch (err) {
      console.error("Shield breach during scan:", err);
      setError("Shield scan interrupted. Re-authenticating...");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const loadFromHistory = (item: ScanHistoryItem) => {
    setOriginalCode(item.original_code);
    setFixedCode(item.fixed_code);
    try {
      const changes = JSON.parse(item.changes_json);
      setResults({ 
        original_code: item.original_code, 
        fixed_code: item.fixed_code, 
        changes_made: changes, 
        summary: item.summary,
        test_script: item.test_script,
        test_result: item.test_result
      });
    } catch (e) {
      setResults(null);
    }
  };

  const clearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear all audit history? This cannot be undone.")) return;
    
    setIsClearing(true);
    try {
      const response = await fetch("/api/history", { method: "DELETE" });
      if (response.ok) {
        setHistory([]);
        setResults(null);
        setFixedCode(DEFAULT_CODE);
      }
    } catch (err) {
      console.error("Failed to clear history:", err);
    } finally {
      setIsClearing(false);
    }
  };

  const applyFixes = () => {
    setOriginalCode(fixedCode);
    // Optionally keep results or clear them
  };

  const startNewAudit = async () => {
    // Save current if there's something meaningful
    if (results || originalCode !== DEFAULT_CODE) {
      await saveScan({
        fixed_code: fixedCode,
        summary: results?.summary || "Auto-saved before new audit",
        changes_made: results?.changes_made || [],
        test_script: results?.test_script,
        test_result: results?.test_result
      });
    }
    
    // Reset workspace
    setOriginalCode(DEFAULT_CODE);
    setFixedCode(DEFAULT_CODE);
    setResults(null);
    setViewMode("editor");
  };

  return (
    <div className={cn(
      "h-screen font-sans overflow-hidden flex flex-col selection:bg-cyan-500/30 transition-colors duration-300",
      theme === "dark" ? "bg-[#0B0E14] text-[#E4E4E7]" : "bg-zinc-50 text-zinc-900"
    )}>
      {/* Header */}
      <header className={cn(
        "border-b backdrop-blur-xl z-50 transition-colors",
        theme === "dark" ? "border-white/5 bg-black/40" : "border-zinc-200 bg-white/80"
      )}>
        <div className="max-w-full mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setShowHistory(!showHistory)}
              className={cn(
                "p-2 rounded-lg transition-colors",
                theme === "dark" ? "hover:bg-white/5 text-zinc-400 hover:text-cyan-400" : "hover:bg-zinc-100 text-zinc-500 hover:text-cyan-600"
              )}
            >
              {showHistory ? <PanelLeftClose className="w-5 h-5" /> : <PanelLeftOpen className="w-5 h-5" />}
            </button>
            <div className="w-10 h-10 bg-cyan-500/10 rounded-xl flex items-center justify-center border border-cyan-500/20 shadow-[0_0_15px_rgba(6,182,212,0.1)]">
              <Shield className="w-6 h-6 text-cyan-500" />
            </div>
            <div>
              <h1 className={cn(
                "text-lg font-bold tracking-tight leading-none",
                theme === "dark" ? "text-white" : "text-zinc-900"
              )}>
                QUANTUM SHIELD AUDITOR
              </h1>
              <p className="text-[10px] text-cyan-500/70 mt-1 font-bold uppercase tracking-widest">
                Real-Time PQC Auto-Fix Dashboard
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button 
              onClick={startNewAudit}
              className={cn(
                "p-2 rounded-xl border transition-all",
                theme === "dark" 
                  ? "bg-zinc-900 border-white/5 text-zinc-400 hover:text-cyan-400" 
                  : "bg-white border-zinc-200 text-zinc-500 hover:text-cyan-600 shadow-sm"
              )}
              title="Start New Audit (Saves current to history)"
            >
              <Plus className="w-4 h-4" />
            </button>
            <button 
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className={cn(
                "p-2 rounded-xl border transition-all",
                theme === "dark" 
                  ? "bg-zinc-900 border-white/5 text-zinc-400 hover:text-cyan-400" 
                  : "bg-white border-zinc-200 text-zinc-500 hover:text-cyan-600 shadow-sm"
              )}
              title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
            <button 
              onClick={() => setShowDashboard(!showDashboard)}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-xl border transition-all text-xs font-semibold",
                showDashboard 
                  ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400" 
                  : theme === "dark" 
                    ? "bg-zinc-900 border-white/5 text-zinc-400 hover:text-white" 
                    : "bg-white border-zinc-200 text-zinc-500 hover:text-zinc-900 shadow-sm"
              )}
            >
              {showDashboard ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
              {showDashboard ? "Hide Dashboard" : "Show Dashboard"}
            </button>
            <div className={cn(
              "hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border",
              theme === "dark" ? "bg-zinc-900/50 border-white/5" : "bg-zinc-100 border-zinc-200"
            )}>
              <Sparkles className="w-4 h-4 text-cyan-500" />
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-tighter">Shield Active</span>
            </div>
            {results && (
              <button 
                onClick={applyFixes}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all shadow-[0_0_15px_rgba(16,185,129,0.2)]"
              >
                <Check className="w-4 h-4" />
                Apply All Fixes
              </button>
            )}
          </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar: History */}
        <AnimatePresence initial={false}>
          {showHistory && (
            <motion.aside 
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: 320, opacity: 1 }}
              exit={{ width: 0, opacity: 0 }}
              className={cn(
                "border-r flex flex-col overflow-hidden transition-colors",
                theme === "dark" ? "border-white/5 bg-black/20" : "border-zinc-200 bg-white"
              )}
            >
              <div className={cn(
                "px-6 py-4 border-b flex flex-col gap-4",
                theme === "dark" ? "border-white/5" : "border-zinc-100"
              )}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <History className="w-4 h-4 text-cyan-500" />
                    <h3 className={cn(
                      "text-xs font-bold uppercase tracking-widest",
                      theme === "dark" ? "text-zinc-400" : "text-zinc-500"
                    )}>Audit History</h3>
                  </div>
                  {history.length > 0 && (
                    <button 
                      onClick={clearHistory}
                      disabled={isClearing}
                      className="p-1.5 hover:bg-red-500/10 rounded-md transition-colors text-zinc-500 hover:text-red-500"
                      title="Clear All History"
                    >
                      <Trash2 className={cn("w-3.5 h-3.5", isClearing && "animate-pulse")} />
                    </button>
                  )}
                </div>
                
                <div className="space-y-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
                    <input 
                      type="text"
                      placeholder="Search logs..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className={cn(
                        "w-full border rounded-lg py-2 pl-9 pr-4 text-xs transition-colors focus:outline-none focus:border-cyan-500/30",
                        theme === "dark" 
                          ? "bg-zinc-900/50 border-white/5 text-zinc-300 placeholder:text-zinc-600" 
                          : "bg-zinc-50 border-zinc-200 text-zinc-900 placeholder:text-zinc-400"
                      )}
                    />
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => setSortBy("date")}
                      className={cn(
                        "flex-1 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all border",
                        sortBy === "date" 
                          ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400" 
                          : theme === "dark"
                            ? "bg-zinc-900/30 border-white/5 text-zinc-500 hover:text-zinc-300"
                            : "bg-zinc-50 border-zinc-200 text-zinc-400 hover:text-zinc-600"
                      )}
                    >
                      Recent
                    </button>
                    <button 
                      onClick={() => setSortBy("fixes")}
                      className={cn(
                        "flex-1 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all border",
                        sortBy === "fixes" 
                          ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400" 
                          : theme === "dark"
                            ? "bg-zinc-900/30 border-white/5 text-zinc-500 hover:text-zinc-300"
                            : "bg-zinc-50 border-zinc-200 text-zinc-400 hover:text-zinc-600"
                      )}
                    >
                      Fixes
                    </button>
                  </div>
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                {filteredHistory.length === 0 ? (
                  <div className="text-center py-20 text-zinc-600">
                    <Clock className="w-12 h-12 mx-auto mb-4 opacity-10" />
                    <p className="text-xs">{searchQuery ? "No matches found." : "No logs found."}</p>
                  </div>
                ) : (
                  filteredHistory.map((item) => (
                    <button 
                      key={item.id}
                      onClick={() => loadFromHistory(item)}
                      className={cn(
                        "w-full text-left p-4 border rounded-xl transition-all group",
                        theme === "dark"
                          ? "bg-zinc-900/30 border-white/5 hover:border-cyan-500/40"
                          : "bg-white border-zinc-200 hover:border-cyan-500/40 shadow-sm"
                      )}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-[10px] font-mono text-zinc-500">
                          {new Date(item.created_at).toLocaleTimeString()}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 bg-cyan-500/10 text-cyan-500 rounded border border-cyan-500/20 font-bold">
                          {item.issue_count} FIXES
                        </span>
                      </div>
                      <p className={cn(
                        "text-[11px] line-clamp-2 leading-relaxed",
                        theme === "dark" ? "text-zinc-400" : "text-zinc-600"
                      )}>
                        {item.summary}
                      </p>
                    </button>
                  ))
                )}
              </div>
            </motion.aside>
          )}
        </AnimatePresence>

        {/* Main Content: DiffEditor or Report */}
        <div className="flex-1 flex flex-col overflow-hidden relative">
          {results && (
            <div className={cn(
              "flex items-center gap-1 p-1 m-4 self-center rounded-xl border z-30 transition-colors",
              theme === "dark" ? "bg-black/40 border-white/5" : "bg-white border-zinc-200 shadow-sm"
            )}>
              <button 
                onClick={() => setViewMode("editor")}
                className={cn(
                  "flex items-center gap-2 px-4 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all",
                  viewMode === "editor" 
                    ? "bg-cyan-500 text-white shadow-lg" 
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                <FileCode className="w-3.5 h-3.5" />
                Diff Editor
              </button>
              <button 
                onClick={() => setViewMode("report")}
                className={cn(
                  "flex items-center gap-2 px-4 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all",
                  viewMode === "report" 
                    ? "bg-cyan-500 text-white shadow-lg" 
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                <ClipboardCheck className="w-3.5 h-3.5" />
                Security Report
              </button>
            </div>
          )}

          <div className={cn(
            "flex-1 relative",
            theme === "dark" ? "bg-[#1e1e1e]" : "bg-white"
          )}>
            {viewMode === "editor" ? (
              <DiffEditor
                height="100%"
                original={originalCode}
                modified={fixedCode}
                language="javascript"
                theme={theme === "dark" ? "vs-dark" : "light"}
                onMount={(editor) => {
                  const originalEditor = editor.getOriginalEditor();
                  originalEditor.onDidChangeModelContent(() => {
                    setOriginalCode(originalEditor.getValue());
                  });
                  const modifiedEditor = editor.getModifiedEditor();
                  modifiedEditor.onDidChangeModelContent(() => {
                    setFixedCode(modifiedEditor.getValue());
                  });
                }}
                options={{
                  fontSize: 14,
                  fontFamily: "'JetBrains Mono', monospace",
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  renderSideBySide: true,
                  padding: { top: 20 },
                  originalEditable: true,
                }}
              />
            ) : (
              <div className={cn(
                "h-full overflow-y-auto p-8 custom-scrollbar",
                theme === "dark" ? "bg-[#0B0E14]" : "bg-zinc-50"
              )}>
                <div className="max-w-4xl mx-auto space-y-8">
                  <header className="space-y-2">
                    <h2 className={cn(
                      "text-2xl font-bold tracking-tight",
                      theme === "dark" ? "text-white" : "text-zinc-900"
                    )}>Security Audit Report</h2>
                    <p className="text-zinc-500 text-sm leading-relaxed">
                      {results?.summary}
                    </p>
                  </header>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className={cn(
                      "p-6 rounded-3xl border",
                      theme === "dark" ? "bg-zinc-900/50 border-white/5" : "bg-white border-zinc-200 shadow-sm"
                    )}>
                      <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Total Issues</p>
                      <p className="text-3xl font-bold text-cyan-500">{results?.changes_made.length}</p>
                    </div>
                    <div className={cn(
                      "p-6 rounded-3xl border",
                      theme === "dark" ? "bg-zinc-900/50 border-white/5" : "bg-white border-zinc-200 shadow-sm"
                    )}>
                      <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Criticality</p>
                      <p className="text-3xl font-bold text-red-500">
                        {results?.changes_made.filter(c => c.severity === "Critical").length}
                      </p>
                    </div>
                    <div className={cn(
                      "p-6 rounded-3xl border",
                      theme === "dark" ? "bg-zinc-900/50 border-white/5" : "bg-white border-zinc-200 shadow-sm"
                    )}>
                      <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Status</p>
                      <p className={cn(
                        "text-3xl font-bold",
                        results?.test_result === "passed" ? "text-emerald-500" : "text-red-500"
                      )}>
                        {results?.test_result?.toUpperCase()}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className={cn(
                      "text-sm font-bold uppercase tracking-widest",
                      theme === "dark" ? "text-zinc-400" : "text-zinc-600"
                    )}>Vulnerability Breakdown</h3>
                    <div className="space-y-3">
                      {results?.changes_made.map((change, idx) => (
                        <div key={idx} className={cn(
                          "p-6 rounded-3xl border flex flex-col md:flex-row gap-6 transition-all",
                          theme === "dark" ? "bg-zinc-900/30 border-white/5" : "bg-white border-zinc-200 shadow-sm"
                        )}>
                          <div className="flex-1 space-y-3">
                            <div className="flex items-center gap-3">
                              <span className="text-[10px] font-bold text-cyan-500 uppercase px-2 py-1 bg-cyan-500/10 rounded-lg">Line {change.line}</span>
                              <span className={cn(
                                "text-[10px] px-2 py-1 rounded-lg font-bold uppercase",
                                change.severity === "Critical" ? "bg-red-500/10 text-red-500" : "bg-yellow-500/10 text-yellow-500"
                              )}>
                                {change.severity}
                              </span>
                            </div>
                            <h4 className={cn(
                              "text-lg font-bold",
                              theme === "dark" ? "text-zinc-100" : "text-zinc-800"
                            )}>{change.issue}</h4>
                          </div>
                          <div className={cn(
                            "flex-1 p-4 rounded-2xl border flex flex-col justify-center",
                            theme === "dark" ? "bg-black/20 border-white/5" : "bg-zinc-50 border-zinc-100"
                          )}>
                            <div className="flex items-center gap-2 mb-2">
                              <ShieldCheck className="w-4 h-4 text-emerald-500" />
                              <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">Recommended Fix</span>
                            </div>
                            <p className="text-sm text-zinc-500 leading-relaxed italic">
                              {change.fix}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Progress Indicator Overlay */}
            <AnimatePresence>
              {isAnalyzing && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className={cn(
                    "absolute inset-0 z-40 backdrop-blur-md flex flex-col items-center justify-center",
                    theme === "dark" ? "bg-[#0B0E14]/80" : "bg-white/80"
                  )}
                >
                  <div className="w-full max-w-md px-12 space-y-8">
                    <div className="relative flex items-center justify-center">
                      <div className="w-32 h-32 border-4 border-cyan-500/10 border-t-cyan-500 rounded-full animate-spin" />
                      <div className="absolute inset-0 flex items-center justify-center">
                        <Shield className="w-12 h-12 text-cyan-500 animate-pulse" />
                      </div>
                      <motion.div 
                        animate={{ 
                          scale: [1, 1.2, 1],
                          opacity: [0.3, 0.6, 0.3]
                        }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="absolute w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl"
                      />
                    </div>
                    
                    <div className="space-y-4 text-center">
                      <h3 className={cn(
                        "text-xl font-bold tracking-tight uppercase",
                        theme === "dark" ? "text-white" : "text-zinc-900"
                      )}>
                        Quantum Shield Scan
                      </h3>
                      <p className="text-xs text-cyan-500/70 font-bold uppercase tracking-[0.3em] animate-pulse">
                        Analyzing Cryptographic Primitives
                      </p>
                      
                      <div className={cn(
                        "h-1 w-full rounded-full overflow-hidden border",
                        theme === "dark" ? "bg-white/5 border-white/5" : "bg-zinc-100 border-zinc-200"
                      )}>
                        <motion.div 
                          initial={{ width: "0%" }}
                          animate={{ width: "100%" }}
                          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
                          className="h-full bg-gradient-to-r from-cyan-600 to-blue-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                        />
                      </div>
                      
                      <div className="flex justify-between text-[10px] font-mono text-zinc-500 uppercase">
                        <span>PQC-Analysis</span>
                        <span>OWASP-Audit</span>
                        <span>Shield-Active</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Controls Overlay */}
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 z-20 w-full max-w-lg px-6 flex gap-3">
            <button
              onClick={() => saveScan({ 
                fixed_code: fixedCode, 
                original_code: originalCode,
                summary: results?.summary || "Manual Save", 
                changes_made: results?.changes_made || [],
                test_script: results?.test_script,
                test_result: results?.test_result
              })}
              disabled={isSaving || isAnalyzing}
              className={cn(
                "px-6 py-4 rounded-2xl font-bold flex items-center justify-center gap-3 transition-all active:scale-[0.98] border relative",
                saveStatus === "success" 
                  ? "bg-emerald-500/10 border-emerald-500/50 text-emerald-500"
                  : saveStatus === "error"
                    ? "bg-red-500/10 border-red-500/50 text-red-500"
                    : theme === "dark" 
                      ? "bg-zinc-900 border-white/10 text-zinc-400 hover:text-white hover:border-white/20" 
                      : "bg-white border-zinc-200 text-zinc-600 hover:text-zinc-900 shadow-lg"
              )}
              title="Save current state to history"
            >
              {isSaving ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : saveStatus === "success" ? (
                <CheckCircle2 className="w-5 h-5" />
              ) : saveStatus === "error" ? (
                <AlertTriangle className="w-5 h-5" />
              ) : (
                <Save className="w-5 h-5" />
              )}
              {saveStatus === "success" && (
                <motion.span 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="absolute -top-10 left-1/2 -translate-x-1/2 px-3 py-1 bg-emerald-500 text-white text-[10px] rounded-full font-bold uppercase tracking-widest pointer-events-none"
                >
                  Saved
                </motion.span>
              )}
            </button>
            
            <button
              onClick={initiateShieldScan}
              disabled={isAnalyzing || !originalCode.trim()}
              className={cn(
                "flex-1 py-4 rounded-2xl font-bold flex items-center justify-center gap-3 transition-all active:scale-[0.98] text-sm tracking-widest uppercase",
                isAnalyzing 
                  ? theme === "dark" ? "bg-zinc-800 text-zinc-500 cursor-not-allowed" : "bg-zinc-200 text-zinc-400 cursor-not-allowed"
                  : "bg-cyan-600 hover:bg-cyan-500 text-white shadow-[0_0_25px_rgba(6,182,212,0.4)] ring-1 ring-white/10"
              )}
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  Shield Scan Active...
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" />
                  Initiate Shield Scan
                </>
              )}
            </button>
          </div>
        </div>

        {/* Sidebar: Changes Dashboard */}
        <AnimatePresence initial={false}>
          {showDashboard && results && (
            <motion.aside 
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: 380, opacity: 1 }}
              exit={{ width: 0, opacity: 0 }}
              className={cn(
                "border-l flex flex-col overflow-hidden transition-colors",
                theme === "dark" ? "border-white/5 bg-black/20" : "border-zinc-200 bg-white"
              )}
            >
              <div className={cn(
                "px-6 py-4 border-b flex items-center justify-between transition-colors",
                theme === "dark" ? "border-white/5 bg-black/40" : "border-zinc-100 bg-zinc-50"
              )}>
                <div className="flex items-center gap-2">
                  <LayoutDashboard className="w-4 h-4 text-cyan-500" />
                  <h3 className={cn(
                    "text-xs font-bold uppercase tracking-widest",
                    theme === "dark" ? "text-zinc-400" : "text-zinc-500"
                  )}>Changes Made</h3>
                </div>
                <div className="flex items-center gap-2">
                  <button 
                    onClick={() => {
                      navigator.clipboard.writeText(fixedCode);
                      const btn = document.getElementById('copy-fixed-btn');
                      if (btn) {
                        const originalHtml = btn.innerHTML;
                        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-emerald-500"><polyline points="20 6 9 17 4 12"/></svg>';
                        setTimeout(() => { btn.innerHTML = originalHtml; }, 2000);
                      }
                    }}
                    id="copy-fixed-btn"
                    className="p-1.5 hover:bg-white/5 rounded-md transition-colors text-zinc-500 hover:text-cyan-400"
                    title="Copy Fixed Code"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                  <button 
                    onClick={() => {
                      const blob = new Blob([fixedCode], { type: 'text/javascript' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'fixed_code.js';
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="p-1.5 hover:bg-white/5 rounded-md transition-colors text-zinc-500 hover:text-cyan-400"
                    title="Download Fixed Code"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                  <button onClick={() => setShowDashboard(false)} className="text-zinc-500 hover:text-white ml-2">
                    <PanelLeftClose className="w-4 h-4 rotate-180" />
                  </button>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                {/* Test Result Banner */}
                {results.test_result && (
                  <div className={cn(
                    "p-4 rounded-2xl border flex items-center gap-3 mb-4",
                    results.test_result === "passed" 
                      ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" 
                      : "bg-red-500/10 border-red-500/20 text-red-400"
                  )}>
                    {results.test_result === "passed" ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-widest">Verification Status</p>
                      <p className="text-xs font-bold">{results.test_result === "passed" ? "TESTS PASSED" : "TESTS FAILED"}</p>
                    </div>
                  </div>
                )}

                {results.changes_made.map((change, idx) => (
                  <div key={idx} className={cn(
                    "p-4 rounded-2xl border space-y-2 transition-colors",
                    theme === "dark" ? "bg-zinc-900/30 border-white/5" : "bg-zinc-50 border-zinc-200"
                  )}>
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-bold text-cyan-500 uppercase">Line {change.line}</span>
                      <span className={cn(
                        "text-[9px] px-1.5 py-0.5 rounded font-bold uppercase",
                        change.severity === "Critical" ? "bg-red-500/10 text-red-500" : "bg-yellow-500/10 text-yellow-500"
                      )}>
                        {change.severity}
                      </span>
                    </div>
                    <p className={cn(
                      "text-[11px] font-bold",
                      theme === "dark" ? "text-zinc-200" : "text-zinc-800"
                    )}>{change.issue}</p>
                    <p className="text-[10px] text-zinc-500 italic">Fix: {change.fix}</p>
                  </div>
                ))}

                {/* Test Script Section */}
                {results.test_script && (
                  <div className="mt-6 space-y-2">
                    <div className="flex items-center justify-between px-2">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-3 h-3 text-zinc-500" />
                        <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-500">Verification Script</span>
                      </div>
                      <button 
                        onClick={() => {
                          if (results.test_script) {
                            navigator.clipboard.writeText(results.test_script);
                            const btn = document.getElementById('copy-script-btn');
                            if (btn) {
                              const originalHtml = btn.innerHTML;
                              btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-check-circle-2 text-emerald-500"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/><path d="m9 12 2 2 4-4"/></svg>';
                              setTimeout(() => { btn.innerHTML = originalHtml; }, 2000);
                            }
                          }
                        }}
                        id="copy-script-btn"
                        className={cn(
                          "p-1.5 rounded-md transition-colors",
                          theme === "dark" ? "hover:bg-white/5 text-zinc-500 hover:text-cyan-400" : "hover:bg-zinc-100 text-zinc-400 hover:text-cyan-600"
                        )}
                        title="Copy Script"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                    <div className={cn(
                      "p-4 rounded-2xl border font-mono text-[10px] overflow-x-auto relative group transition-colors",
                      theme === "dark" ? "bg-black/40 border-white/5 text-zinc-400" : "bg-zinc-50 border-zinc-200 text-zinc-600"
                    )}>
                      <pre>{results.test_script}</pre>
                    </div>
                  </div>
                )}
              </div>
              <div className={cn(
                "p-6 border-t transition-colors",
                theme === "dark" ? "bg-cyan-500/5 border-white/5" : "bg-cyan-50/50 border-zinc-100"
              )}>
                <p className={cn(
                  "text-[11px] leading-relaxed italic",
                  theme === "dark" ? "text-cyan-400/80" : "text-cyan-600/80"
                )}>
                  {results.summary}
                </p>
              </div>
            </motion.aside>
          )}
        </AnimatePresence>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(6, 182, 212, 0.1);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(6, 182, 212, 0.3);
        }
      `}} />
    </div>
  );
}
