import { useState } from 'react';
import { Gauge, Play, Terminal } from 'lucide-react';
import { HealthResponse, TestSuiteResponse, api } from '../api/client';
import { ErrorBanner, StatusPill } from '../components/Common';

const QUANTUM_IMPACT_MATRIX = [
  { algo: 'RSA-2048', attack: "Shor's Algorithm", effect: 'Factoring becomes polynomial time', verdict: 'Vulnerable', safe: false },
  { algo: 'ECC (P-256)', attack: "Shor's Algorithm", effect: 'Discrete log becomes polynomial time', verdict: 'Vulnerable', safe: false },
  { algo: 'AES-128', attack: "Grover's Algorithm", effect: 'Effective strength drops from 128 to 64 bits', verdict: 'Weakened', safe: false },
  { algo: 'AES-256', attack: "Grover's Algorithm", effect: 'Retains ~128-bit post-quantum security', verdict: 'Safe', safe: true },
  { algo: 'SHA-512', attack: "Grover's Algorithm", effect: 'Retains ~256-bit pre-image resistance', verdict: 'Safe', safe: true },
];

export function TestBenchView({ health }: { health: HealthResponse | null }) {
  const [loading, setLoading] = useState(false);
  const [activeSuite, setActiveSuite] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [res, setRes] = useState<TestSuiteResponse | null>(null);

  const handleRun = async (suite: 'all' | 'q1' | 'q2' | 'q3' | 'bench') => {
    setError(null);
    setLoading(true);
    setActiveSuite(suite);
    try {
      const data = await api.runTests(suite);
      setRes(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test execution failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {health && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl bg-[#f2efe9] px-4 py-2.5 text-xs text-[#4e5665]">
          <StatusPill ok={health.cpp_ready} passLabel="C++ Engines Ready" failLabel="Build Incomplete" />
          <span className="font-mono-data">Qiskit {health.qiskit_version}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {[
          { id: 'all', label: 'Run All (Q1–Q3)' },
          { id: 'q1', label: 'Q1 · AES + RSA' },
          { id: 'q2', label: 'Q2 · 18 ECC/SHA Checks' },
          { id: 'q3', label: 'Q3 · 4 Quantum Tests' },
        ].map((btn) => (
          <button
            key={btn.id}
            type="button"
            disabled={loading}
            onClick={() => handleRun(btn.id as 'all' | 'q1' | 'q2' | 'q3')}
            className={`inline-flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-semibold transition-colors disabled:opacity-55 ${
              btn.id === 'all'
                ? 'bg-[#047857] text-white hover:bg-[#065f46]'
                : 'bg-[#f2efe9] text-[#141821] hover:bg-[#e5e0d6]'
            }`}
          >
            <Play className="h-3.5 w-3.5" />
            <span>{loading && activeSuite === btn.id ? 'Running...' : btn.label}</span>
          </button>
        ))}
        <button
          type="button"
          disabled={loading}
          onClick={() => handleRun('bench')}
          className="inline-flex items-center gap-1.5 rounded-xl bg-[#fff7ed] px-3.5 py-2 text-xs font-semibold text-[#9a3412] hover:bg-[#ffedd5] disabled:opacity-55"
        >
          <Gauge className="h-3.5 w-3.5" />
          <span>{loading && activeSuite === 'bench' ? 'Running...' : 'Speed Benchmarks'}</span>
        </button>
      </div>

      <ErrorBanner message={error} />

      {res && (
        <div className="space-y-2.5">
          {res.results.map((item) => (
            <details key={item.id} open className="overflow-hidden rounded-xl bg-[#f5f3ee]">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-xs font-semibold text-[#141821]">
                <div className="flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 text-[#767f90]" />
                  <span>{item.title}</span>
                </div>
                <div className="flex items-center gap-2.5">
                  <span className="font-mono-data font-normal text-[#767f90]">{item.elapsed_ms} ms</span>
                  <StatusPill ok={item.passed} passLabel="PASS" failLabel="FAIL" />
                </div>
              </summary>
              <pre className="dark-scroll max-h-56 overflow-auto bg-[#11161f] p-3.5 font-mono-data text-[11px] leading-relaxed text-[#e2e8f0]">
                {item.output}
              </pre>
            </details>
          ))}
        </div>
      )}

      <div className="overflow-hidden rounded-xl bg-[#f5f3ee]">
        <div className="px-4 py-3 text-xs font-semibold text-[#141821]">
          Post-Quantum Security Summary
        </div>
        <div className="overflow-x-auto bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f4] text-[#767f90]">
              <tr>
                <th className="px-4 py-2 font-semibold">Algorithm</th>
                <th className="px-4 py-2 font-semibold">Quantum Threat</th>
                <th className="px-4 py-2 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#efece4]">
              {QUANTUM_IMPACT_MATRIX.map((row) => (
                <tr key={row.algo}>
                  <td className="px-4 py-2.5 font-semibold text-[#141821]">{row.algo}</td>
                  <td className="px-4 py-2.5 text-[#4e5665]">{row.effect}</td>
                  <td className="px-4 py-2.5">
                    <StatusPill ok={row.safe} passLabel={row.verdict} failLabel={row.verdict} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
