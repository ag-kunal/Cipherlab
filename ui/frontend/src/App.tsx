import { useCallback, useEffect, useState } from 'react';
import { Atom, FlaskConical, Lock, ShieldCheck, X } from 'lucide-react';
import { HealthResponse, QuantumHandoff, api } from './api/client';
import { ClassicalLab } from './views/ClassicalLab';
import { QuantumAttackLab } from './views/QuantumAttackLab';
import { TestBenchView } from './views/TestBenchView';

type StudioMode = 'classical' | 'quantum';

export function App() {
  const [mode, setMode] = useState<StudioMode>('classical');
  const [testsOpen, setTestsOpen] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [handoff, setHandoff] = useState<QuantumHandoff | null>(null);

  useEffect(() => {
    void api.health().then(setHealth).catch(() => {});
  }, []);

  const handleSendToQuantum = useCallback((nextHandoff: QuantumHandoff) => {
    setHandoff(nextHandoff);
    setMode('quantum');
  }, []);

  const handleClearHandoff = useCallback(() => {
    setHandoff(null);
  }, []);

  return (
    <div className="min-h-screen bg-[#f5f3ee] text-[#141821] flex flex-col">
      {/* Clean floating header */}
      <header className="sticky top-0 z-30 border-b border-[#e5e0d6] bg-[#f5f3ee]/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-3.5 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div
              className={`flex h-9 w-9 items-center justify-center rounded-xl text-white transition-colors ${
                mode === 'quantum' ? 'bg-[#c2410c]' : 'bg-[#047857]'
              }`}
            >
              <ShieldCheck className="h-5 w-5" />
            </div>
            <span className="text-base font-bold tracking-tight text-[#141821]">CipherLab</span>
          </div>

          {/* Primary 2-mode pill switch */}
          <nav
            aria-label="Studio mode"
            className="flex items-center rounded-full bg-[#e8e4da] p-1"
          >
            <button
              type="button"
              onClick={() => setMode('classical')}
              className={`inline-flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-semibold transition-all sm:text-sm ${
                mode === 'classical'
                  ? 'bg-white text-[#047857] shadow-xs'
                  : 'text-[#4e5665] hover:text-[#141821]'
              }`}
            >
              <Lock className="h-3.5 w-3.5" />
              <span>Encrypt &amp; Hash</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('quantum')}
              className={`inline-flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-semibold transition-all sm:text-sm ${
                mode === 'quantum'
                  ? 'bg-white text-[#c2410c] shadow-xs'
                  : 'text-[#4e5665] hover:text-[#141821]'
              }`}
            >
              <Atom className="h-3.5 w-3.5" />
              <span>Quantum Attack</span>
            </button>
          </nav>

          <button
            type="button"
            onClick={() => setTestsOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-full border border-[#ddd7cb] bg-white px-3 py-1.5 text-xs font-medium text-[#4e5665] transition-colors hover:bg-[#faf8f4] hover:text-[#141821]"
          >
            <FlaskConical className="h-3.5 w-3.5" />
            <span>Lab Tests</span>
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        <div className="mb-6">
          <h1 className="text-2xl font-bold tracking-tight text-[#141821] sm:text-3xl">
            {mode === 'classical'
              ? 'Protect messages, verify signatures, and hash text'
              : 'Reverse locks and hashes with simulated quantum attacks'}
          </h1>
          <p className="mt-1.5 max-w-2xl text-sm text-[#4e5665]">
            {mode === 'classical'
              ? 'Enter any text below, pick an encryption or hashing tool, and instantly generate or verify the result.'
              : 'Provide an encrypted output, public point, or SHA-512 fingerprint — or send one straight from Encrypt & Hash — to watch Shor and Grover recover the secret.'}
          </p>
        </div>

        {mode === 'classical' ? (
          <ClassicalLab onSendToQuantum={handleSendToQuantum} />
        ) : (
          <QuantumAttackLab
            health={health}
            handoff={handoff}
            onClearHandoff={handleClearHandoff}
          />
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-[#e5e0d6] bg-[#f5f3ee]">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-4 py-4 text-xs text-[#767f90] sm:px-6">
          <span>AES-256 · RSA · SHA-512 · Elliptic Curve (P-256) · Quantum Shor &amp; Grover</span>
          <span>Local cryptographic engine · Runs entirely on your machine</span>
        </div>
      </footer>

      {/* Slide-over Verification Drawer */}
      {testsOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-[#141821]/40 backdrop-blur-[2px]">
          <div
            role="dialog"
            aria-label="Assignment verification suites"
            className="flex h-full w-full max-w-2xl flex-col bg-white shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-[#efece4] px-6 py-4">
              <div>
                <h2 className="text-base font-bold text-[#141821]">Assignment Verification &amp; Benchmarks</h2>
                <p className="text-xs text-[#767f90]">
                  Run the underlying Q1–Q3 verification tests and post-quantum summary
                </p>
              </div>
              <button
                type="button"
                onClick={() => setTestsOpen(false)}
                aria-label="Close verification panel"
                className="rounded-lg p-1.5 text-[#767f90] hover:bg-[#f2efe9] hover:text-[#141821]"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6">
              <TestBenchView health={health} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
