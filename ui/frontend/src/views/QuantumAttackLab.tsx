import { ReactNode, useEffect, useState } from 'react';
import {
  Atom,
  CheckCircle2,
  Fingerprint,
  KeyRound,
  LockOpen,
  Play,
  ShieldAlert,
  Sparkles,
} from 'lucide-react';
import {
  GroverAESResponse,
  GroverSHA512Response,
  HealthResponse,
  QuantumAlgorithm,
  QuantumHandoff,
  ShorECCResponse,
  ShorRSAResponse,
  api,
} from '../api/client';
import {
  Disclosure,
  ErrorBanner,
  OutputField,
  ShotChart,
  StatusPill,
} from '../components/Common';

const QUANTUM_ATTACKS: {
  id: QuantumAlgorithm;
  title: string;
  desc: string;
  icon: typeof Atom;
}[] = [
  { id: 'shor_rsa', title: 'Break RSA Lock', desc: "Shor's key-factoring attack", icon: KeyRound },
  { id: 'shor_ecc', title: 'Find Secret ECC Key', desc: "Shor's curve attack", icon: Atom },
  { id: 'grover_aes', title: 'Crack Weak AES Key', desc: "Grover's key search", icon: LockOpen },
  { id: 'grover_sha512', title: 'Reverse SHA-512 Hash', desc: "Grover's hash pre-image", icon: Fingerprint },
];

const RSA_OPTIONS: Record<number, { e: number; a: number; label: string }> = {
  15: { e: 7, a: 2, label: 'Demo key N = 15 (fast · 8 qubits)' },
  21: { e: 5, a: 2, label: 'Demo key N = 21 (10 qubits)' },
  33: { e: 7, a: 7, label: 'Demo key N = 33 (11 qubits)' },
  35: { e: 5, a: 2, label: 'Demo key N = 35 (11 qubits)' },
};

const REAL_WORLD_TAKEAWAYS: Record<QuantumAlgorithm, string> = {
  shor_rsa:
    'This runs Shor’s period-finding circuit on a small demo key. On a large fault-tolerant quantum computer, the same method breaks full RSA-2048.',
  shor_ecc:
    'Shor’s Fourier sampling recovers the hidden ECC private key directly from the public point. Real-world ECC curves (like P-256) face the same vulnerability.',
  grover_aes:
    'Grover’s search cuts brute-force work by a square root. AES-128 weakens to ~64-bit strength, while AES-256 stays safe at ~128-bit post-quantum strength.',
  grover_sha512:
    'Grover’s algorithm finds a matching string quadratically faster inside a small search space, but a real 512-bit hash would still take ~2²⁵⁶ steps — completely impractical.',
};

export function QuantumAttackLab({
  health,
  handoff,
  onClearHandoff,
}: {
  health: HealthResponse | null;
  handoff: QuantumHandoff | null;
  onClearHandoff: () => void;
}) {
  const [algo, setAlgo] = useState<QuantumAlgorithm>('shor_rsa');
  const [shots, setShots] = useState(4096);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [handoffBanner, setHandoffBanner] = useState<string | null>(null);

  // Shor RSA state
  const [rsaN, setRsaN] = useState(21);
  const [rsaE, setRsaE] = useState(5);
  const [rsaInputMode, setRsaInputMode] = useState<'text' | 'number'>('text');
  const [rsaMessageNum, setRsaMessageNum] = useState('17');
  const [rsaText, setRsaText] = useState('Hi!');
  const [rsaCipherInput, setRsaCipherInput] = useState('');
  const [shorRsaRes, setShorRsaRes] = useState<ShorRSAResponse | null>(null);

  // Shor ECC state
  const [eccTargetD, setEccTargetD] = useState(3);
  const [eccCustomPoint, setEccCustomPoint] = useState('');
  const [shorEccRes, setShorEccRes] = useState<ShorECCResponse | null>(null);

  // Grover AES state
  const [groverAesPlaintext, setGroverAesPlaintext] = useState('Meet at noon');
  const [groverAesBits, setGroverAesBits] = useState(4);
  const [groverAesSecretK, setGroverAesSecretK] = useState('11');
  const [groverAesCipherHex, setGroverAesCipherHex] = useState('');
  const [groverAesRes, setGroverAesRes] = useState<GroverAESResponse | null>(null);

  // Grover SHA-512 state
  const [groverShaPrefix, setGroverShaPrefix] = useState('toy-preimage-');
  const [groverShaSuffixMode, setGroverShaSuffixMode] = useState<'raw_byte' | 'decimal_ascii' | 'hex_char'>('decimal_ascii');
  const [groverShaBits, setGroverShaBits] = useState(4);
  const [groverShaSecretK, setGroverShaSecretK] = useState('9');
  const [groverShaDigestHex, setGroverShaDigestHex] = useState('');
  const [groverShaCandidates, setGroverShaCandidates] = useState<string[] | null>(null);
  const [groverShaRes, setGroverShaRes] = useState<GroverSHA512Response | null>(null);

  useEffect(() => {
    if (!handoff) return;
    setAlgo(handoff.algorithm);
    setError(null);
    setHandoffBanner(handoff.sourceLabel ?? 'Loaded target output from Classical mode.');

    if (handoff.algorithm === 'shor_rsa') {
      if (handoff.rsaTextMode !== undefined) {
        setRsaInputMode(handoff.rsaTextMode ? 'text' : 'number');
      }
      if (handoff.rsaTextInput) setRsaText(handoff.rsaTextInput);
      setRsaCipherInput('');
    } else if (handoff.algorithm === 'grover_sha512') {
      if (handoff.shaCandidates) {
        setGroverShaCandidates(handoff.shaCandidates);
      } else {
        setGroverShaCandidates(null);
      }
      if (handoff.shaPrefix !== undefined) setGroverShaPrefix(handoff.shaPrefix);
      if (handoff.shaSuffixMode) setGroverShaSuffixMode(handoff.shaSuffixMode);
      if (handoff.shaN) setGroverShaBits(handoff.shaN);
      if (handoff.shaDigestHex) setGroverShaDigestHex(handoff.shaDigestHex);
    }
    onClearHandoff();
  }, [handoff, onClearHandoff]);

  const runQuantumAttack = async () => {
    setError(null);
    setLoading(true);
    try {
      if (algo === 'shor_rsa') {
        const parsedCiphers = rsaCipherInput
          .trim()
          .split(/[\s,]+/)
          .filter(Boolean)
          .map((x) => Number(x));
        const res = await api.shorRsa({
          N: rsaN,
          e: rsaE,
          a: RSA_OPTIONS[rsaN]?.a,
          input_mode: rsaInputMode,
          message_value: rsaInputMode === 'number' ? Number(rsaMessageNum) : null,
          text_input: rsaInputMode === 'text' ? rsaText : null,
          ciphertext_values: parsedCiphers.length > 0 ? parsedCiphers : null,
          shots,
        });
        setShorRsaRes(res);
      } else if (algo === 'shor_ecc') {
        let pt: [number, number] | null = null;
        if (eccCustomPoint.trim()) {
          const parts = eccCustomPoint.replace(/[()]/g, '').split(',').map((s) => Number(s.trim()));
          if (parts.length !== 2 || parts.some(Number.isNaN)) {
            throw new Error('Enter a coordinate like 10, 3');
          }
          pt = [parts[0], parts[1]];
        }
        const res = await api.shorEcc({
          target_d: pt ? null : eccTargetD,
          public_point: pt,
          shots,
        });
        setShorEccRes(res);
      } else if (algo === 'grover_aes') {
        const res = await api.groverAes({
          plaintext: groverAesPlaintext,
          secret_k: groverAesCipherHex.trim() ? null : Number(groverAesSecretK),
          target_ciphertext_hex: groverAesCipherHex.trim() || null,
          n_bits: groverAesBits,
          shots,
        });
        setGroverAesRes(res);
      } else if (algo === 'grover_sha512') {
        const res = await api.groverSha512({
          prefix: groverShaPrefix,
          suffix_mode: groverShaSuffixMode,
          secret_k: groverShaDigestHex.trim() ? null : Number(groverShaSecretK),
          target_digest_hex: groverShaDigestHex.trim() || null,
          n_bits: groverShaBits,
          shots,
          candidates: groverShaCandidates,
        });
        setGroverShaRes(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Quantum simulation failed.');
    } finally {
      setLoading(false);
    }
  };

  const subgroup = health?.toy_ecc.subgroup ?? [
    { k: 1, point: [4, 6] as [number, number] },
    { k: 2, point: [14, 15] as [number, number] },
    { k: 3, point: [10, 3] as [number, number] },
    { k: 4, point: [7, 0] as [number, number] },
    { k: 5, point: [10, 14] as [number, number] },
    { k: 6, point: [14, 2] as [number, number] },
    { k: 7, point: [4, 11] as [number, number] },
  ];

  return (
    <div className="quantum-scope space-y-6 animate-panel-in">
      {/* Attack method cards */}
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
        {QUANTUM_ATTACKS.map((item) => {
          const Icon = item.icon;
          const active = algo === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setAlgo(item.id);
                setError(null);
              }}
              className={`rounded-2xl p-3.5 text-left transition-all ${
                active
                  ? 'bg-[#c2410c] text-white shadow-md shadow-[#c2410c]/20'
                  : 'bg-white text-[#141821] hover:bg-[#fcfbf8] stage-shadow'
              }`}
            >
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-xl ${
                  active ? 'bg-white/15 text-white' : 'bg-[#fff7ed] text-[#c2410c]'
                }`}
              >
                <Icon className="h-4 w-4" />
              </div>
              <div className="mt-2.5 text-sm font-semibold">{item.title}</div>
              <div className={`mt-0.5 text-xs ${active ? 'text-[#fed7aa]' : 'text-[#767f90]'}`}>
                {item.desc}
              </div>
            </button>
          );
        })}
      </div>

      {handoffBanner && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-[#fff7ed] px-4 py-2.5 text-xs font-medium text-[#9a3412]">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-[#c2410c]" />
            <span>{handoffBanner}</span>
          </div>
          <button
            type="button"
            onClick={() => setHandoffBanner(null)}
            className="text-xs font-semibold underline hover:no-underline"
          >
            Dismiss
          </button>
        </div>
      )}

      <ErrorBanner message={error} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: Target Input */}
        <section className="rounded-2xl bg-white p-6 stage-shadow lg:col-span-5">
          {algo === 'shor_rsa' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Break RSA Lock</h2>
                <p className="text-xs text-[#767f90]">
                  Lock a short message with a public RSA key and watch Shor’s algorithm crack the key and unlock it.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-1 rounded-xl bg-[#f2efe9] p-1">
                {(['text', 'number'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setRsaInputMode(m)}
                    className={`rounded-lg py-2 text-xs font-semibold transition-all ${
                      rsaInputMode === m
                        ? 'bg-white text-[#c2410c] shadow-xs'
                        : 'text-[#4e5665] hover:text-[#141821]'
                    }`}
                  >
                    {m === 'text' ? 'Crack Text Message' : 'Crack Number'}
                  </button>
                ))}
              </div>

              {rsaInputMode === 'text' ? (
                <div className="space-y-2">
                  <label className="block text-xs font-semibold text-[#141821]">
                    Message to lock &amp; break
                  </label>
                  <input
                    type="text"
                    value={rsaText}
                    onChange={(e) => setRsaText(e.target.value)}
                    placeholder="Short message (e.g. Hi!)"
                    className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821]"
                  />
                  <div className="flex flex-wrap gap-1.5">
                    {['Hi!', 'Secret', 'Code 7'].map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => {
                          setRsaText(s);
                          setRsaCipherInput('');
                        }}
                        className="rounded-full bg-[#f2efe9] px-2.5 py-1 text-[11px] font-medium text-[#4e5665] hover:bg-[#e5e0d6]"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <label className="block text-xs font-semibold text-[#141821]">
                    Number to lock &amp; break
                  </label>
                  <input
                    type="number"
                    value={rsaMessageNum}
                    onChange={(e) => setRsaMessageNum(e.target.value)}
                    className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 font-mono-data text-sm"
                  />
                </div>
              )}

              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#141821]">Simulated key size</label>
                <select
                  value={rsaN}
                  onChange={(e) => {
                    const nextN = Number(e.target.value);
                    setRsaN(nextN);
                    setRsaE(RSA_OPTIONS[nextN].e);
                  }}
                  className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-xs font-medium text-[#141821]"
                >
                  {Object.entries(RSA_OPTIONS).map(([nVal, info]) => (
                    <option key={nVal} value={nVal}>
                      {info.label}
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={runQuantumAttack}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#c2410c] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#9a3412] active:scale-[0.99] disabled:opacity-60"
              >
                <Atom className="h-4 w-4" />
                <span>{loading ? 'Running Quantum Circuit...' : 'Run Quantum Attack'}</span>
              </button>

              <Disclosure title="Advanced target & simulation settings">
                <div className="space-y-3 pt-1 text-xs">
                  <div className="space-y-1">
                    <label className="block text-[#4e5665]">Paste encrypted numbers directly (optional)</label>
                    <input
                      type="text"
                      value={rsaCipherInput}
                      onChange={(e) => setRsaCipherInput(e.target.value)}
                      placeholder="Leave empty to auto-encrypt message above"
                      className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                    />
                  </div>
                  <ShotsRow shots={shots} setShots={setShots} />
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'shor_ecc' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Find Secret ECC Key</h2>
                <p className="text-xs text-[#767f90]">
                  Pick a public key point on the curve. The quantum computer will deduce the hidden secret multiplier.
                </p>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-semibold text-[#141821]">
                  Choose a public key to attack
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {subgroup.slice(0, 6).map((entry, idx) => {
                    const active = !eccCustomPoint && eccTargetD === entry.k;
                    return (
                      <button
                        key={entry.k}
                        type="button"
                        onClick={() => {
                          setEccTargetD(entry.k);
                          setEccCustomPoint('');
                        }}
                        className={`rounded-xl px-3 py-2.5 text-left text-xs transition-all ${
                          active
                            ? 'bg-[#fff7ed] font-semibold text-[#9a3412] ring-1 ring-[#fb923c]'
                            : 'bg-[#f5f3ee] text-[#4e5665] hover:bg-[#ebe6dc]'
                        }`}
                      >
                        <div>Public Key #{idx + 1}</div>
                        <div className="mt-0.5 font-mono-data text-[11px] opacity-80">
                          Point ({entry.point[0]}, {entry.point[1]})
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={runQuantumAttack}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#c2410c] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#9a3412] active:scale-[0.99] disabled:opacity-60"
              >
                <Atom className="h-4 w-4" />
                <span>{loading ? 'Sampling Quantum States...' : 'Recover Private Key'}</span>
              </button>

              <Disclosure title="Advanced point & simulation settings">
                <div className="space-y-3 pt-1 text-xs">
                  <div className="space-y-1">
                    <label className="block text-[#4e5665]">Custom public point Q (x, y)</label>
                    <input
                      type="text"
                      value={eccCustomPoint}
                      onChange={(e) => setEccCustomPoint(e.target.value)}
                      placeholder="e.g. 10, 3"
                      className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                    />
                  </div>
                  <ShotsRow shots={shots} setShots={setShots} />
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'grover_aes' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Crack Weak AES Key</h2>
                <p className="text-xs text-[#767f90]">
                  Grover’s quantum search finds the hidden key out of all possible keys and decrypts the message.
                </p>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-semibold text-[#141821]">
                  Message locked with a weak key
                </label>
                <input
                  type="text"
                  value={groverAesPlaintext}
                  onChange={(e) => setGroverAesPlaintext(e.target.value)}
                  className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-[#141821]">Key search space</label>
                  <select
                    value={groverAesBits}
                    onChange={(e) => setGroverAesBits(Number(e.target.value))}
                    className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2.5 text-xs font-medium"
                  >
                    <option value={4}>16 possible keys (4 qubits)</option>
                    <option value={5}>32 possible keys (5 qubits)</option>
                    <option value={6}>64 possible keys (6 qubits)</option>
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-[#141821]">
                    Hidden key slot (0–{(1 << groverAesBits) - 1})
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={(1 << groverAesBits) - 1}
                    value={groverAesSecretK}
                    onChange={(e) => setGroverAesSecretK(e.target.value)}
                    disabled={groverAesCipherHex.trim().length > 0}
                    className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2.5 font-mono-data text-xs disabled:opacity-50"
                  />
                </div>
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={runQuantumAttack}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#c2410c] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#9a3412] active:scale-[0.99] disabled:opacity-60"
              >
                <Play className="h-4 w-4" />
                <span>{loading ? 'Searching Quantum Space...' : 'Find Key & Unlock Message'}</span>
              </button>

              <Disclosure title="Advanced target ciphertext & shots">
                <div className="space-y-3 pt-1 text-xs">
                  <div className="space-y-1">
                    <label className="block text-[#4e5665]">Paste 32-char hex ciphertext (optional)</label>
                    <input
                      type="text"
                      value={groverAesCipherHex}
                      onChange={(e) => setGroverAesCipherHex(e.target.value)}
                      placeholder="Auto-generated if left blank"
                      className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                    />
                  </div>
                  <ShotsRow shots={shots} setShots={setShots} />
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'grover_sha512' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Reverse SHA-512 Hash</h2>
                <p className="text-xs text-[#767f90]">
                  Given a digital fingerprint, Grover’s search checks possibilities in parallel to recover the original string.
                </p>
              </div>

              {groverShaCandidates ? (
                <div className="space-y-2 rounded-xl bg-[#fff7ed] p-3.5 text-xs text-[#9a3412]">
                  <div className="font-semibold">Searching 16 candidate strings for your fingerprint</div>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {groverShaCandidates.slice(0, 6).map((c) => (
                      <span key={c} className="rounded bg-white px-2 py-0.5 font-mono-data text-[11px] text-[#4e5665]">
                        {c}
                      </span>
                    ))}
                    <span className="px-1 text-[#9a3412]">+10 more</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setGroverShaCandidates(null);
                      setGroverShaDigestHex('');
                    }}
                    className="pt-1 font-semibold underline hover:no-underline"
                  >
                    Switch back to prefix + number mode
                  </button>
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    <label className="block text-xs font-semibold text-[#141821]">
                      Quick examples (prefix + hidden number)
                    </label>
                    <div className="flex flex-wrap gap-1.5">
                      {[
                        { label: 'toy-preimage-9', prefix: 'toy-preimage-', k: '9' },
                        { label: 'pin-code-12', prefix: 'pin-code-', k: '12' },
                        { label: 'user-5', prefix: 'user-', k: '5' },
                      ].map((ex) => (
                        <button
                          key={ex.label}
                          type="button"
                          onClick={() => {
                            setGroverShaPrefix(ex.prefix);
                            setGroverShaSecretK(ex.k);
                            setGroverShaSuffixMode('decimal_ascii');
                            setGroverShaDigestHex('');
                          }}
                          className="rounded-full bg-[#f2efe9] px-2.5 py-1 text-[11px] font-medium text-[#4e5665] hover:bg-[#e5e0d6]"
                        >
                          {ex.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <div className="col-span-2 space-y-1.5">
                      <label className="block text-xs font-semibold text-[#141821]">Prefix</label>
                      <input
                        type="text"
                        value={groverShaPrefix}
                        onChange={(e) => setGroverShaPrefix(e.target.value)}
                        className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2 text-xs"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="block text-xs font-semibold text-[#141821]">Secret #</label>
                      <input
                        type="number"
                        min={0}
                        max={(1 << groverShaBits) - 1}
                        value={groverShaSecretK}
                        onChange={(e) => setGroverShaSecretK(e.target.value)}
                        disabled={groverShaDigestHex.trim().length > 0}
                        className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2 font-mono-data text-xs disabled:opacity-50"
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#141821]">
                  Target SHA-512 fingerprint (optional)
                </label>
                <textarea
                  rows={2}
                  value={groverShaDigestHex}
                  onChange={(e) => setGroverShaDigestHex(e.target.value)}
                  placeholder="Auto-computed from above, or paste a 128-char SHA-512 hash..."
                  className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2 font-mono-data text-xs"
                />
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={runQuantumAttack}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#c2410c] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#9a3412] active:scale-[0.99] disabled:opacity-60"
              >
                <Play className="h-4 w-4" />
                <span>{loading ? 'Reversing Fingerprint...' : 'Recover Original String'}</span>
              </button>

              {!groverShaCandidates && (
                <Disclosure title="Advanced search space & simulation settings">
                  <div className="space-y-3 pt-1 text-xs">
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className="mb-1 block text-[#4e5665]">Suffix encoding</label>
                        <select
                          value={groverShaSuffixMode}
                          onChange={(e) =>
                            setGroverShaSuffixMode(e.target.value as 'raw_byte' | 'decimal_ascii' | 'hex_char')
                          }
                          className="w-full rounded-lg bg-white px-2 py-1.5 text-xs"
                        >
                          <option value="decimal_ascii">Number text (e.g. 9)</option>
                          <option value="raw_byte">Raw byte (0x09)</option>
                          <option value="hex_char">Hex char (0–f)</option>
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-[#4e5665]">Search size</label>
                        <select
                          value={groverShaBits}
                          onChange={(e) => setGroverShaBits(Number(e.target.value))}
                          className="w-full rounded-lg bg-white px-2 py-1.5 text-xs"
                        >
                          <option value={4}>16 items (4 qubits)</option>
                          <option value={5}>32 items (5 qubits)</option>
                          <option value={6}>64 items (6 qubits)</option>
                        </select>
                      </div>
                    </div>
                    <ShotsRow shots={shots} setShots={setShots} />
                  </div>
                </Disclosure>
              )}
            </div>
          )}
        </section>

        {/* Right: Dark Obsidian Attack Telemetry */}
        <section className="rounded-2xl bg-[#11161f] p-6 text-[#f8fafc] obsidian-shadow lg:col-span-7">
          {algo === 'shor_rsa' && (
            <AttackStage
              title="RSA Break Result"
              hasResult={Boolean(shorRsaRes)}
              verified={Boolean(shorRsaRes?.verified && shorRsaRes?.factorization_check)}
              emptyText="Click Run Quantum Attack to watch Shor's algorithm factor the key and unlock your message."
              takeaway={REAL_WORLD_TAKEAWAYS.shor_rsa}
            >
              {shorRsaRes && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <StepCard step="1. Key Factored" value={`${shorRsaRes.N} = ${shorRsaRes.factors.join(' × ')}`} />
                    <StepCard step="2. Private Key Found" value={`d = ${shorRsaRes.recovered_d ?? '—'}`} />
                    <StepCard
                      step="3. Unlocked Secret"
                      value={
                        shorRsaRes.input_mode === 'text'
                          ? shorRsaRes.recovered_text ?? ''
                          : shorRsaRes.decrypted_values.join(', ')
                      }
                      highlight
                    />
                  </div>
                  <OutputField
                    dark
                    label="Encrypted Values Broken"
                    value={shorRsaRes.target_ciphertexts.join(' ')}
                  />
                  <Disclosure dark title="Inspect quantum circuit measurements">
                    <div className="pt-2">
                      <ShotChart counts={shorRsaRes.counts} shots={shorRsaRes.shots} maxRows={8} />
                    </div>
                  </Disclosure>
                </div>
              )}
            </AttackStage>
          )}

          {algo === 'shor_ecc' && (
            <AttackStage
              title="ECC Key Recovery Result"
              hasResult={Boolean(shorEccRes)}
              verified={Boolean(shorEccRes?.verified)}
              emptyText="Select any public key point on the left and click Recover Private Key."
              takeaway={REAL_WORLD_TAKEAWAYS.shor_ecc}
            >
              {shorEccRes && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <StepCard
                      step="1. Public Point Attacked"
                      value={`(${shorEccRes.Q[0]}, ${shorEccRes.Q[1]})`}
                    />
                    <StepCard
                      step="2. Quantum Qubits Used"
                      value={`${shorEccRes.n_qubits} qubits`}
                    />
                    <StepCard
                      step="3. Secret Key Recovered"
                      value={`d = ${shorEccRes.recovered_d ?? '—'}`}
                      highlight
                    />
                  </div>
                  <Disclosure dark title="Inspect quantum Fourier measurements">
                    <div className="pt-2">
                      <ShotChart counts={shorEccRes.joint_counts} shots={shorEccRes.shots} maxRows={8} />
                    </div>
                  </Disclosure>
                </div>
              )}
            </AttackStage>
          )}

          {algo === 'grover_aes' && (
            <AttackStage
              title="AES Key Search Result"
              hasResult={Boolean(groverAesRes)}
              verified={Boolean(groverAesRes?.verified)}
              emptyText="Click Find Key & Unlock Message to watch Grover's search amplify the hidden key."
              takeaway={REAL_WORLD_TAKEAWAYS.grover_aes}
            >
              {groverAesRes && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <StepCard
                      step="1. Quantum Confidence"
                      value={`${groverAesRes.top_probability_pct}% match`}
                    />
                    <StepCard
                      step="2. Key Slot Found"
                      value={`Key #${groverAesRes.recovered_k}`}
                    />
                    <StepCard
                      step="3. Unlocked Message"
                      value={groverAesRes.decrypted_text}
                      highlight
                    />
                  </div>
                  <OutputField
                    dark
                    label="Recovered 128-bit AES Key"
                    value={groverAesRes.recovered_key_hex}
                  />
                  <Disclosure dark title="Inspect quantum probability amplification">
                    <div className="pt-2">
                      <ShotChart counts={groverAesRes.counts} shots={groverAesRes.shots} maxRows={8} />
                    </div>
                  </Disclosure>
                </div>
              )}
            </AttackStage>
          )}

          {algo === 'grover_sha512' && (
            <AttackStage
              title="SHA-512 Pre-Image Result"
              hasResult={Boolean(groverShaRes)}
              verified={Boolean(groverShaRes?.verified)}
              emptyText="Click Recover Original String to let Grover's search find the string matching the fingerprint."
              takeaway={REAL_WORLD_TAKEAWAYS.grover_sha512}
            >
              {groverShaRes && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <StepCard
                      step="1. Quantum Confidence"
                      value={`${groverShaRes.top_probability_pct}% peak`}
                    />
                    <StepCard
                      step="2. Quantum Steps"
                      value={`${groverShaRes.iterations} iteration(s)`}
                    />
                    <StepCard
                      step="3. Original String Found"
                      value={groverShaRes.recovered_message_text}
                      highlight
                    />
                  </div>
                  <OutputField
                    dark
                    label="Matched SHA-512 Fingerprint"
                    value={groverShaRes.target_digest_hex}
                  />
                  <Disclosure dark title="Inspect quantum amplitude spikes">
                    <div className="pt-2">
                      <ShotChart counts={groverShaRes.counts} shots={groverShaRes.shots} maxRows={8} />
                    </div>
                  </Disclosure>
                </div>
              )}
            </AttackStage>
          )}
        </section>
      </div>
    </div>
  );
}

function AttackStage({
  title,
  hasResult,
  verified,
  emptyText,
  takeaway,
  children,
}: {
  title: string;
  hasResult: boolean;
  verified: boolean;
  emptyText: string;
  takeaway: string;
  children: ReactNode;
}) {
  return (
    <div className="flex h-full flex-col justify-between space-y-5">
      <div className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
          <h3 className="text-base font-semibold text-white">{title}</h3>
          {hasResult && (
            <StatusPill dark ok={verified} passLabel="Secret Recovered" failLabel="Mismatch" />
          )}
        </div>

        {!hasResult ? (
          <div className="flex min-h-64 flex-col items-center justify-center rounded-xl bg-[#1a212e]/60 p-8 text-center">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/5 text-[#fbbf24]">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <p className="mt-3 max-w-sm text-xs leading-relaxed text-[#94a3b8]">{emptyText}</p>
          </div>
        ) : (
          children
        )}
      </div>

      <div className="flex items-start gap-2.5 rounded-xl bg-[#1a212e]/80 px-4 py-3 text-xs leading-relaxed text-[#cbd5e1]">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#fbbf24]" />
        <span>{takeaway}</span>
      </div>
    </div>
  );
}

function StepCard({
  step,
  value,
  highlight = false,
}: {
  step: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={`rounded-xl p-3.5 ${
        highlight
          ? 'bg-[#064e3b]/45 ring-1 ring-[#10b981]/35'
          : 'bg-[#1a212e]'
      }`}
    >
      <div className={`text-[11px] font-medium ${highlight ? 'text-[#6ee7b7]' : 'text-[#94a3b8]'}`}>
        {step}
      </div>
      <div
        className={`mt-1 break-words font-mono-data text-sm font-bold ${
          highlight ? 'text-[#ecfdf5]' : 'text-white'
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function ShotsRow({ shots, setShots }: { shots: number; setShots: (n: number) => void }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[#4e5665]">Quantum sample shots</span>
      <select
        value={shots}
        onChange={(e) => setShots(Number(e.target.value))}
        className="rounded-lg bg-white px-2.5 py-1 font-mono-data text-xs"
      >
        <option value={1024}>1,024</option>
        <option value={2048}>2,048</option>
        <option value={4096}>4,096 (default)</option>
        <option value={8192}>8,192</option>
      </select>
    </div>
  );
}
