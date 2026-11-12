import { useState } from 'react';
import {
  ArrowRight,
  Atom,
  Eye,
  EyeOff,
  FileSignature,
  Fingerprint,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Unlock,
  Users,
} from 'lucide-react';
import {
  AES256Response,
  ClassicalAlgorithm,
  ECDHResponse,
  ECDSAResponse,
  QuantumHandoff,
  RSAResponse,
  SHA512Response,
  api,
} from '../api/client';
import {
  Disclosure,
  ErrorBanner,
  OutputField,
  StateMatrixGrid,
  StatusPill,
} from '../components/Common';

const NIST_AES_KEY = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';

const ALGORITHMS: {
  id: ClassicalAlgorithm;
  title: string;
  desc: string;
  icon: typeof Lock;
}[] = [
  { id: 'aes256', title: 'AES-256 Lock', desc: 'Lock text with a password', icon: Lock },
  { id: 'rsa', title: 'RSA Key Lock', desc: 'Public-key text encryption', icon: KeyRound },
  { id: 'sha512', title: 'SHA-512 Hash', desc: 'One-way digital fingerprint', icon: Fingerprint },
  { id: 'ecdsa', title: 'Digital Signature', desc: 'Prove nothing was tampered', icon: FileSignature },
  { id: 'ecdh', title: 'Shared Secret', desc: 'Agree on a key over public net', icon: Users },
];

const DECOY_WORDS = [
  'quantum', 'cipher', 'sunrise', 'notebook', 'harbor', 'cactus',
  'velocity', 'lantern', 'cobalt', 'whisper', 'diamond', 'glacier',
  'orbit', 'meadow', 'beacon', 'ember', 'anchor', 'compass',
];

function buildCandidateSpace(secretText: string): { candidates: string[]; secretIndex: number } {
  const clean = secretText || 'hello';
  const pool = DECOY_WORDS.filter((w) => w !== clean).slice(0, 15);
  while (pool.length < 15) {
    pool.push(`item-${pool.length + 1}`);
  }
  const secretIndex = 9;
  const candidates = [...pool.slice(0, secretIndex), clean, ...pool.slice(secretIndex)];
  return { candidates, secretIndex };
}

export function ClassicalLab({
  onSendToQuantum,
}: {
  onSendToQuantum: (handoff: QuantumHandoff) => void;
}) {
  const [algo, setAlgo] = useState<ClassicalAlgorithm>('aes256');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // AES-256 state (password-first UX)
  const [aesAction, setAesAction] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [aesInput, setAesInput] = useState('Meet me by the harbor at 7 PM.');
  const [aesPassphrase, setAesPassphrase] = useState('ocean-breeze-42');
  const [showPass, setShowPass] = useState(false);
  const [aesKeyMode, setAesKeyMode] = useState<'passphrase' | 'hex'>('passphrase');
  const [aesKeyHex, setAesKeyHex] = useState(NIST_AES_KEY);
  const [aesEncoding, setAesEncoding] = useState<'utf8' | 'hex'>('utf8');
  const [aesPadding, setAesPadding] = useState<'pkcs7' | 'none'>('pkcs7');
  const [aesRes, setAesRes] = useState<AES256Response | null>(null);

  // RSA state
  const [rsaAction, setRsaAction] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [rsaInput, setRsaInput] = useState('Hello RSA!');
  const [rsaType, setRsaType] = useState<'text' | 'number'>('text');
  const [rsaP, setRsaP] = useState('1009');
  const [rsaQ, setRsaQ] = useState('1013');
  const [rsaE, setRsaE] = useState('65537');
  const [rsaRes, setRsaRes] = useState<RSAResponse | null>(null);

  // SHA-512 state
  const [shaText, setShaText] = useState('Hello cryptography');
  const [shaAvalanche, setShaAvalanche] = useState(true);
  const [shaRes, setShaRes] = useState<SHA512Response | null>(null);

  // ECDSA state
  const [ecdsaMessage, setEcdsaMessage] = useState('Approve transfer of $250 to Maya');
  const [ecdsaPriv, setEcdsaPriv] = useState('auto');
  const [ecdsaPubX, setEcdsaPubX] = useState('');
  const [ecdsaPubY, setEcdsaPubY] = useState('');
  const [ecdsaR, setEcdsaR] = useState('');
  const [ecdsaS, setEcdsaS] = useState('');
  const [ecdsaRes, setEcdsaRes] = useState<ECDSAResponse | null>(null);

  // ECDH state
  const [ecdhAlicePriv, setEcdhAlicePriv] = useState('auto');
  const [ecdhBobPriv, setEcdhBobPriv] = useState('auto');
  const [ecdhMessage, setEcdhMessage] = useState('Private message over our shared key');
  const [ecdhRes, setEcdhRes] = useState<ECDHResponse | null>(null);

  const runAction = async (overrideAction?: string) => {
    setError(null);
    setLoading(true);
    try {
      if (algo === 'aes256') {
        const act = (overrideAction as 'encrypt' | 'decrypt') || aesAction;
        if (!aesInput.trim()) throw new Error('Enter a message or encrypted code first.');
        if (aesKeyMode === 'passphrase' && !aesPassphrase.trim()) {
          throw new Error('Enter a password to lock or unlock your message.');
        }
        const data = await api.aes256({
          action: act,
          input_data: aesInput,
          input_encoding: act === 'decrypt' ? 'hex' : aesEncoding,
          key_hex: aesKeyMode === 'hex' ? aesKeyHex : null,
          passphrase: aesKeyMode === 'passphrase' ? aesPassphrase : null,
          padding: aesPadding,
        });
        setAesRes(data);
      } else if (algo === 'rsa') {
        const act = (overrideAction as 'encrypt' | 'decrypt') || rsaAction;
        if (!rsaInput.trim()) throw new Error('Enter text or numbers to process with RSA.');
        const data = await api.rsa({
          action: act,
          input_type: rsaType,
          input_data: rsaInput,
          p: Number(rsaP),
          q: Number(rsaQ),
          e: Number(rsaE),
        });
        setRsaRes(data);
      } else if (algo === 'sha512') {
        const data = await api.sha512({
          text: shaText,
          avalanche_check: shaAvalanche,
        });
        setShaRes(data);
      } else if (algo === 'ecdsa') {
        const act = (overrideAction as 'keygen' | 'sign' | 'verify') || 'sign';
        const data = await api.ecdsa({
          action: act,
          message: ecdsaMessage,
          priv_hex: ecdsaPriv || 'auto',
          pub_x: ecdsaPubX,
          pub_y: ecdsaPubY,
          r: ecdsaR,
          s: ecdsaS,
        });
        setEcdsaRes(data);
        if (act === 'keygen' || act === 'sign') {
          if (data.priv_hex) setEcdsaPriv(data.priv_hex);
          if (data.pub) {
            setEcdsaPubX(data.pub.x);
            setEcdsaPubY(data.pub.y);
          }
          if (data.signature) {
            setEcdsaR(data.signature.r);
            setEcdsaS(data.signature.s);
          }
        }
      } else if (algo === 'ecdh') {
        const data = await api.ecdh({
          alice_priv_hex: ecdhAlicePriv || 'auto',
          bob_priv_hex: ecdhBobPriv || 'auto',
          optional_message: ecdhMessage,
        });
        setEcdhRes(data);
        setEcdhAlicePriv(data.alice_priv);
        setEcdhBobPriv(data.bob_priv);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong running this operation.');
    } finally {
      setLoading(false);
    }
  };

  const generateRandomAesKey = () => {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    const hex = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    setAesKeyMode('hex');
    setAesKeyHex(hex);
  };

  const handleShaToQuantum = () => {
    if (!shaRes) return;
    const match = shaText.match(/^(.*?)(\d+)$/);
    if (match && Number(match[2]) >= 0 && Number(match[2]) <= 63) {
      const kNum = Number(match[2]);
      const nBits = kNum < 16 ? 4 : kNum < 32 ? 5 : 6;
      onSendToQuantum({
        algorithm: 'grover_sha512',
        sourceLabel: `Your SHA-512 fingerprint for "${shaText}"`,
        shaPrefix: match[1],
        shaSuffixMode: 'decimal_ascii',
        shaDigestHex: shaRes.digest_hex,
        shaN: nBits,
        shaOriginalText: shaText,
      });
      return;
    }
    const { candidates } = buildCandidateSpace(shaText);
    onSendToQuantum({
      algorithm: 'grover_sha512',
      sourceLabel: `Your SHA-512 fingerprint for "${shaText}"`,
      shaDigestHex: shaRes.digest_hex,
      shaN: 4,
      shaCandidates: candidates,
      shaOriginalText: shaText,
    });
  };

  return (
    <div className="space-y-6 animate-panel-in">
      {/* Method cards */}
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
        {ALGORITHMS.map((item) => {
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
              className={`group rounded-2xl p-3.5 text-left transition-all ${
                active
                  ? 'bg-[#047857] text-white shadow-md shadow-[#047857]/20'
                  : 'bg-white text-[#141821] hover:bg-[#fcfbf8] stage-shadow'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div
                  className={`flex h-8 w-8 items-center justify-center rounded-xl transition-colors ${
                    active ? 'bg-white/15 text-white' : 'bg-[#ecfdf5] text-[#047857]'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                </div>
              </div>
              <div className="mt-2.5 text-sm font-semibold">{item.title}</div>
              <div className={`mt-0.5 text-xs ${active ? 'text-[#d1fae5]' : 'text-[#767f90]'}`}>
                {item.desc}
              </div>
            </button>
          );
        })}
      </div>

      <ErrorBanner message={error} />

      {/* Main unified stage */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: User Input Card */}
        <section className="rounded-2xl bg-white p-6 stage-shadow lg:col-span-5">
          {algo === 'aes256' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold tracking-tight text-[#141821]">AES-256 Lock</h2>
                  <p className="text-xs text-[#767f90]">
                    Scrambles your message so only someone with the password can read it.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-1 rounded-xl bg-[#f2efe9] p-1">
                {(['encrypt', 'decrypt'] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => {
                      setAesAction(mode);
                      if (mode === 'decrypt') setAesEncoding('hex');
                      else setAesEncoding('utf8');
                    }}
                    className={`rounded-lg py-2 text-xs font-semibold transition-all ${
                      aesAction === mode
                        ? 'bg-white text-[#047857] shadow-xs'
                        : 'text-[#4e5665] hover:text-[#141821]'
                    }`}
                  >
                    {mode === 'encrypt' ? 'Lock Message' : 'Unlock Ciphertext'}
                  </button>
                ))}
              </div>

              <div className="space-y-2">
                <label htmlFor="aes-input" className="block text-xs font-semibold text-[#141821]">
                  {aesAction === 'encrypt' ? 'Your message' : 'Encrypted code to unlock'}
                </label>
                <textarea
                  id="aes-input"
                  rows={3}
                  value={aesInput}
                  onChange={(e) => setAesInput(e.target.value)}
                  placeholder={
                    aesAction === 'encrypt'
                      ? 'Type any secret message...'
                      : 'Paste the encrypted hex output...'
                  }
                  className={`w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821] placeholder:text-[#94a3b8] ${
                    aesAction === 'decrypt' || aesEncoding === 'hex' ? 'font-mono-data text-xs' : ''
                  }`}
                />
                {aesAction === 'encrypt' && (
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      'Meet me at 9 PM',
                      'Flight code: ALPHA-409',
                      'Top secret project notes',
                    ].map((sample) => (
                      <button
                        key={sample}
                        type="button"
                        onClick={() => {
                          setAesEncoding('utf8');
                          setAesPadding('pkcs7');
                          setAesInput(sample);
                        }}
                        className="rounded-full bg-[#f2efe9] px-2.5 py-1 text-[11px] font-medium text-[#4e5665] transition-colors hover:bg-[#e5e0d6] hover:text-[#141821]"
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {aesKeyMode === 'passphrase' ? (
                <div className="space-y-2">
                  <label htmlFor="aes-pass" className="block text-xs font-semibold text-[#141821]">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      id="aes-pass"
                      type={showPass ? 'text' : 'password'}
                      value={aesPassphrase}
                      onChange={(e) => setAesPassphrase(e.target.value)}
                      placeholder="Enter a secret password"
                      className="w-full rounded-xl bg-[#f5f3ee] py-2.5 pl-3.5 pr-10 text-sm text-[#141821]"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass((v) => !v)}
                      aria-label={showPass ? 'Hide password' : 'Show password'}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-1 text-[#767f90] hover:text-[#141821]"
                    >
                      {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-[#141821]">256-bit Hex Key</label>
                    <button
                      type="button"
                      onClick={generateRandomAesKey}
                      className="inline-flex items-center gap-1 text-xs font-medium text-[#047857] hover:underline"
                    >
                      <RefreshCw className="h-3 w-3" /> Random key
                    </button>
                  </div>
                  <textarea
                    rows={2}
                    value={aesKeyHex}
                    onChange={(e) => setAesKeyHex(e.target.value)}
                    className="w-full rounded-xl bg-[#f5f3ee] px-3 py-2 font-mono-data text-xs text-[#141821]"
                  />
                </div>
              )}

              <button
                type="button"
                disabled={loading}
                onClick={() => runAction()}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#047857] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#065f46] active:scale-[0.99] disabled:opacity-60"
              >
                {aesAction === 'encrypt' ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
                <span>
                  {loading
                    ? 'Processing...'
                    : aesAction === 'encrypt'
                    ? 'Encrypt Message'
                    : 'Decrypt Message'}
                </span>
              </button>

              <Disclosure title="Advanced options (raw hex key & padding)">
                <div className="space-y-3 pt-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[#4e5665]">Key format</span>
                    <div className="flex gap-1">
                      {(['passphrase', 'hex'] as const).map((m) => (
                        <button
                          key={m}
                          type="button"
                          onClick={() => setAesKeyMode(m)}
                          className={`rounded-md px-2.5 py-1 font-medium ${
                            aesKeyMode === m ? 'bg-[#141821] text-white' : 'bg-white text-[#4e5665]'
                          }`}
                        >
                          {m === 'passphrase' ? 'Password' : '64-Char Hex'}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[#4e5665]">Input format</span>
                    <select
                      value={aesEncoding}
                      onChange={(e) => setAesEncoding(e.target.value as 'utf8' | 'hex')}
                      className="rounded-lg bg-white px-2.5 py-1 text-xs text-[#141821]"
                    >
                      <option value="utf8">Normal text (UTF-8)</option>
                      <option value="hex">Raw bytes (Hex)</option>
                    </select>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[#4e5665]">Block padding</span>
                    <select
                      value={aesPadding}
                      onChange={(e) => setAesPadding(e.target.value as 'pkcs7' | 'none')}
                      className="rounded-lg bg-white px-2.5 py-1 text-xs text-[#141821]"
                    >
                      <option value="pkcs7">Automatic (PKCS#7)</option>
                      <option value="none">None (16-byte blocks)</option>
                    </select>
                  </div>
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'rsa' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">RSA Key Lock</h2>
                <p className="text-xs text-[#767f90]">
                  Anyone can lock a message using the public key; only the private key opens it.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-1 rounded-xl bg-[#f2efe9] p-1">
                {(['encrypt', 'decrypt'] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setRsaAction(mode)}
                    className={`rounded-lg py-2 text-xs font-semibold transition-all ${
                      rsaAction === mode
                        ? 'bg-white text-[#047857] shadow-xs'
                        : 'text-[#4e5665] hover:text-[#141821]'
                    }`}
                  >
                    {mode === 'encrypt' ? 'Lock Message' : 'Unlock Numbers'}
                  </button>
                ))}
              </div>

              <div className="space-y-2">
                <label htmlFor="rsa-input" className="block text-xs font-semibold text-[#141821]">
                  {rsaAction === 'encrypt'
                    ? rsaType === 'text'
                      ? 'Your message'
                      : 'Number to encrypt'
                    : 'Encrypted numbers (space-separated)'}
                </label>
                <textarea
                  id="rsa-input"
                  rows={3}
                  value={rsaInput}
                  onChange={(e) => setRsaInput(e.target.value)}
                  className={`w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821] ${
                    rsaAction === 'decrypt' || rsaType === 'number' ? 'font-mono-data' : ''
                  }`}
                />
                {rsaAction === 'encrypt' && rsaType === 'text' && (
                  <div className="flex flex-wrap gap-1.5">
                    {['Hello RSA!', 'Meet at 5', 'Secret'].map((sample) => (
                      <button
                        key={sample}
                        type="button"
                        onClick={() => setRsaInput(sample)}
                        className="rounded-full bg-[#f2efe9] px-2.5 py-1 text-[11px] font-medium text-[#4e5665] hover:bg-[#e5e0d6]"
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={() => runAction()}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#047857] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#065f46] active:scale-[0.99] disabled:opacity-60"
              >
                <KeyRound className="h-4 w-4" />
                <span>
                  {loading ? 'Calculating...' : rsaAction === 'encrypt' ? 'Encrypt with RSA' : 'Decrypt RSA'}
                </span>
              </button>

              <Disclosure title="Advanced key math (primes p, q & mode)">
                <div className="space-y-3 pt-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[#4e5665]">Input type</span>
                    <div className="flex gap-1">
                      {(['text', 'number'] as const).map((t) => (
                        <button
                          key={t}
                          type="button"
                          onClick={() => setRsaType(t)}
                          className={`rounded-md px-2.5 py-1 font-medium capitalize ${
                            rsaType === t ? 'bg-[#141821] text-white' : 'bg-white text-[#4e5665]'
                          }`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="mb-1 block text-[#4e5665]">Prime p</label>
                      <input
                        type="number"
                        value={rsaP}
                        onChange={(e) => setRsaP(e.target.value)}
                        className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-[#4e5665]">Prime q</label>
                      <input
                        type="number"
                        value={rsaQ}
                        onChange={(e) => setRsaQ(e.target.value)}
                        className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-[#4e5665]">Exponent e</label>
                      <input
                        type="number"
                        value={rsaE}
                        onChange={(e) => setRsaE(e.target.value)}
                        className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                      />
                    </div>
                  </div>
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'sha512' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">SHA-512 Fingerprint</h2>
                <p className="text-xs text-[#767f90]">
                  Turns any message into a fixed 128-character fingerprint that cannot be reversed normally.
                </p>
              </div>

              <div className="space-y-2">
                <label htmlFor="sha-input" className="block text-xs font-semibold text-[#141821]">
                  Text to fingerprint
                </label>
                <textarea
                  id="sha-input"
                  rows={4}
                  value={shaText}
                  onChange={(e) => setShaText(e.target.value)}
                  placeholder="Type anything to generate its SHA-512 fingerprint..."
                  className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821]"
                />
                <div className="flex flex-wrap gap-1.5">
                  {['Hello cryptography', 'toy-preimage-9', 'MyPassword'].map((sample) => (
                    <button
                      key={sample}
                      type="button"
                      onClick={() => setShaText(sample)}
                      className="rounded-full bg-[#f2efe9] px-2.5 py-1 text-[11px] font-medium text-[#4e5665] hover:bg-[#e5e0d6]"
                    >
                      {sample}
                    </button>
                  ))}
                </div>
              </div>

              <label className="flex cursor-pointer items-center gap-2.5 rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-xs text-[#4e5665]">
                <input
                  type="checkbox"
                  checked={shaAvalanche}
                  onChange={(e) => setShaAvalanche(e.target.checked)}
                  className="h-4 w-4 accent-[#047857]"
                />
                <span>Also test how a tiny 1-bit edit changes the entire fingerprint</span>
              </label>

              <button
                type="button"
                disabled={loading}
                onClick={() => runAction()}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#047857] px-4 py-3 text-sm font-semibold text-white transition-all hover:bg-[#065f46] active:scale-[0.99] disabled:opacity-60"
              >
                <Fingerprint className="h-4 w-4" />
                <span>{loading ? 'Generating...' : 'Generate Fingerprint'}</span>
              </button>
            </div>
          )}

          {algo === 'ecdsa' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Digital Signature</h2>
                <p className="text-xs text-[#767f90]">
                  Sign a message with your private key, then edit a word to see tampering get caught.
                </p>
              </div>

              <div className="space-y-2">
                <label htmlFor="ecdsa-msg" className="block text-xs font-semibold text-[#141821]">
                  Document or message
                </label>
                <textarea
                  id="ecdsa-msg"
                  rows={3}
                  value={ecdsaMessage}
                  onChange={(e) => setEcdsaMessage(e.target.value)}
                  className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821]"
                />
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => runAction('sign')}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#047857] px-3.5 py-3 text-sm font-semibold text-white hover:bg-[#065f46] disabled:opacity-60"
                >
                  <FileSignature className="h-4 w-4" /> Sign Message
                </button>
                <button
                  type="button"
                  disabled={loading || !ecdsaR || !ecdsaS || !ecdsaPubX}
                  onClick={() => runAction('verify')}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#f2efe9] px-3.5 py-3 text-sm font-semibold text-[#141821] hover:bg-[#e5e0d6] disabled:opacity-45"
                >
                  <ShieldCheck className="h-4 w-4 text-[#047857]" /> Verify
                </button>
              </div>

              {ecdsaR && (
                <div className="rounded-xl bg-[#ecfdf5] px-3.5 py-2.5 text-xs text-[#065f46]">
                  <strong>Try testing tamper detection:</strong> change one number or letter in the
                  message box above and click <strong>Verify</strong>.
                </div>
              )}

              <Disclosure title="Advanced signature & public key values (hex)">
                <div className="space-y-2 pt-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[#4e5665]">Private key</span>
                    <button
                      type="button"
                      onClick={() => {
                        setEcdsaPriv('auto');
                        void runAction('keygen');
                      }}
                      className="font-medium text-[#047857] hover:underline"
                    >
                      Generate new keypair
                    </button>
                  </div>
                  <input
                    type="text"
                    value={ecdsaPriv}
                    onChange={(e) => setEcdsaPriv(e.target.value)}
                    placeholder="Private key (hex or auto)"
                    className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                  />
                  <input
                    type="text"
                    value={ecdsaPubX}
                    onChange={(e) => setEcdsaPubX(e.target.value)}
                    placeholder="Public key X"
                    className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                  />
                  <input
                    type="text"
                    value={ecdsaPubY}
                    onChange={(e) => setEcdsaPubY(e.target.value)}
                    placeholder="Public key Y"
                    className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={ecdsaR}
                      onChange={(e) => setEcdsaR(e.target.value)}
                      placeholder="Signature r"
                      className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                    />
                    <input
                      type="text"
                      value={ecdsaS}
                      onChange={(e) => setEcdsaS(e.target.value)}
                      placeholder="Signature s"
                      className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                    />
                  </div>
                </div>
              </Disclosure>
            </div>
          )}

          {algo === 'ecdh' && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-bold tracking-tight text-[#141821]">Shared Secret</h2>
                <p className="text-xs text-[#767f90]">
                  Alice and Bob exchange public keys and magically arrive at the exact same private encryption key.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2.5 rounded-xl bg-[#f5f3ee] p-3 text-xs">
                <div className="rounded-lg bg-white p-2.5">
                  <div className="font-semibold text-[#141821]">Alice</div>
                  <div className="mt-0.5 text-[#767f90]">Generates keypair &amp; shares public point</div>
                </div>
                <div className="rounded-lg bg-white p-2.5">
                  <div className="font-semibold text-[#141821]">Bob</div>
                  <div className="mt-0.5 text-[#767f90]">Generates keypair &amp; shares public point</div>
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="ecdh-msg" className="block text-xs font-semibold text-[#141821]">
                  Message to send over the shared channel (optional)
                </label>
                <input
                  id="ecdh-msg"
                  type="text"
                  value={ecdhMessage}
                  onChange={(e) => setEcdhMessage(e.target.value)}
                  className="w-full rounded-xl bg-[#f5f3ee] px-3.5 py-2.5 text-sm text-[#141821]"
                />
              </div>

              <button
                type="button"
                disabled={loading}
                onClick={() => runAction()}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-[#047857] px-4 py-3 text-sm font-semibold text-white hover:bg-[#065f46] disabled:opacity-60"
              >
                <Users className="h-4 w-4" />
                <span>{loading ? 'Exchanging Keys...' : 'Create Shared Secret'}</span>
              </button>

              <Disclosure title="Advanced private key scalars">
                <div className="space-y-2 pt-1 text-xs">
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={() => {
                        setEcdhAlicePriv('auto');
                        setEcdhBobPriv('auto');
                      }}
                      className="font-medium text-[#047857] hover:underline"
                    >
                      Randomize both keys
                    </button>
                  </div>
                  <input
                    type="text"
                    value={ecdhAlicePriv}
                    onChange={(e) => setEcdhAlicePriv(e.target.value)}
                    placeholder="Alice private key (hex or auto)"
                    className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                  />
                  <input
                    type="text"
                    value={ecdhBobPriv}
                    onChange={(e) => setEcdhBobPriv(e.target.value)}
                    placeholder="Bob private key (hex or auto)"
                    className="w-full rounded-lg bg-white px-2.5 py-1.5 font-mono-data text-xs"
                  />
                </div>
              </Disclosure>
            </div>
          )}
        </section>

        {/* Right: Dark Obsidian Output Showcase */}
        <section className="rounded-2xl bg-[#11161f] p-6 text-[#f8fafc] obsidian-shadow lg:col-span-7">
          {algo === 'aes256' && (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
                <h3 className="text-base font-semibold text-white">Result</h3>
                {aesRes && (
                  <StatusPill
                    dark
                    ok={aesRes.action === 'encrypt' || aesRes.padding_valid !== false}
                    passLabel={aesRes.action === 'encrypt' ? 'Locked with AES-256' : 'Unlocked'}
                    failLabel="Wrong password or corrupted text"
                  />
                )}
              </div>

              {!aesRes ? (
                <DarkEmptyState
                  icon={Lock}
                  title="Ready to lock your message"
                  subtitle="Type any text on the left and click Encrypt Message to generate AES-256 ciphertext."
                />
              ) : (
                <div className="space-y-4">
                  {aesRes.action === 'encrypt' ? (
                    <>
                      <OutputField
                        dark
                        label="Encrypted Ciphertext"
                        value={aesRes.output_hex}
                        meta={`${aesRes.output_hex.length / 2} bytes`}
                      />
                      <div className="flex flex-wrap gap-2.5">
                        <button
                          type="button"
                          disabled={loading}
                          onClick={async () => {
                            setError(null);
                            setLoading(true);
                            try {
                              setAesAction('decrypt');
                              setAesInput(aesRes.output_hex);
                              const dec = await api.aes256({
                                action: 'decrypt',
                                input_data: aesRes.output_hex,
                                input_encoding: 'hex',
                                key_hex: aesRes.key_hex,
                                padding: aesRes.padding,
                              });
                              setAesRes(dec);
                            } catch (err) {
                              setError(err instanceof Error ? err.message : 'Unlock failed');
                            } finally {
                              setLoading(false);
                            }
                          }}
                          className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-3.5 py-2 text-xs font-semibold text-white hover:bg-white/15 disabled:opacity-50"
                        >
                          <Unlock className="h-3.5 w-3.5 text-[#34d399]" /> Unlock This Back to Plaintext
                        </button>
                      </div>
                    </>
                  ) : (
                    <OutputField
                      dark
                      highlight
                      mono={false}
                      label="Recovered Original Message"
                      value={aesRes.recovered_text ?? ''}
                    />
                  )}

                  <Disclosure dark title="Inspect cryptographic details (key & 4×4 block state)">
                    <div className="space-y-3 pt-2">
                      <OutputField dark label="Derived 256-bit Encryption Key" value={aesRes.key_hex} />
                      {aesRes.blocks[0] && (
                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                          <StateMatrixGrid title="Block 0 · Input" matrix={aesRes.blocks[0].input_state} />
                          <StateMatrixGrid title="Block 0 · Output" matrix={aesRes.blocks[0].output_state} />
                        </div>
                      )}
                    </div>
                  </Disclosure>
                </div>
              )}
            </div>
          )}

          {algo === 'rsa' && (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
                <h3 className="text-base font-semibold text-white">Result</h3>
                {rsaRes && <StatusPill dark ok passLabel="RSA Complete" />}
              </div>

              {!rsaRes ? (
                <DarkEmptyState
                  icon={KeyRound}
                  title="Public-key encryption ready"
                  subtitle="Enter a short message on the left and click Encrypt with RSA."
                />
              ) : (
                <div className="space-y-4">
                  {rsaRes.ciphertext_str !== undefined && (
                    <>
                      <OutputField
                        dark
                        label="Encrypted Numbers"
                        value={rsaRes.ciphertext_str}
                        meta={`${rsaRes.ciphertext_ints?.length ?? 0} values`}
                      />
                      <div className="flex flex-wrap gap-2.5">
                        <button
                          type="button"
                          disabled={loading}
                          onClick={async () => {
                            setError(null);
                            setLoading(true);
                            try {
                              setRsaAction('decrypt');
                              setRsaInput(rsaRes.ciphertext_str!);
                              const dec = await api.rsa({
                                action: 'decrypt',
                                input_type: 'text',
                                input_data: rsaRes.ciphertext_str!,
                                p: rsaRes.keys.p,
                                q: rsaRes.keys.q,
                                e: rsaRes.keys.e,
                              });
                              setRsaRes(dec);
                            } catch (err) {
                              setError(err instanceof Error ? err.message : 'Unlock failed');
                            } finally {
                              setLoading(false);
                            }
                          }}
                          className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-3.5 py-2 text-xs font-semibold text-white hover:bg-white/15"
                        >
                          <Unlock className="h-3.5 w-3.5 text-[#34d399]" /> Decrypt Back to Text
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            onSendToQuantum({
                              algorithm: 'shor_rsa',
                              sourceLabel: `Watch Shor's algorithm break RSA on "${rsaInput.slice(0, 16)}"`,
                              rsaTextMode: true,
                              rsaTextInput: rsaInput.slice(0, 12) || 'Hi!',
                            })
                          }
                          className="inline-flex items-center gap-2 rounded-xl bg-[#c2410c]/25 px-3.5 py-2 text-xs font-semibold text-[#fdba74] ring-1 ring-[#f97316]/30 hover:bg-[#c2410c]/35"
                        >
                          <Atom className="h-3.5 w-3.5" /> See Quantum Break RSA
                          <ArrowRight className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </>
                  )}

                  {rsaRes.recovered_text !== undefined && (
                    <OutputField
                      dark
                      highlight
                      mono={false}
                      label="Recovered Original Text"
                      value={rsaRes.recovered_text}
                    />
                  )}

                  {rsaRes.result !== undefined && (
                    <OutputField
                      dark
                      highlight={rsaRes.action !== 'encrypt_number'}
                      label={rsaRes.action === 'encrypt_number' ? 'Encrypted Number' : 'Decrypted Number'}
                      value={String(rsaRes.result)}
                    />
                  )}

                  <Disclosure dark title="Inspect RSA key math & per-character mapping">
                    <div className="space-y-3 pt-2 text-xs">
                      <div className="grid grid-cols-2 gap-2 rounded-xl bg-[#11161f] p-3 sm:grid-cols-4">
                        <div>
                          <div className="text-[#64748b]">Public n</div>
                          <div className="font-mono-data font-semibold text-white">{rsaRes.keys.n.toLocaleString()}</div>
                        </div>
                        <div>
                          <div className="text-[#64748b]">Totient φ(n)</div>
                          <div className="font-mono-data font-semibold text-white">{rsaRes.keys.phi.toLocaleString()}</div>
                        </div>
                        <div>
                          <div className="text-[#64748b]">Public e</div>
                          <div className="font-mono-data font-semibold text-white">{rsaRes.keys.e}</div>
                        </div>
                        <div>
                          <div className="text-[#64748b]">Private d</div>
                          <div className="font-mono-data font-semibold text-[#6ee7b7]">{rsaRes.keys.d.toLocaleString()}</div>
                        </div>
                      </div>
                      {rsaRes.breakdown && rsaRes.breakdown.length > 0 && (
                        <div className="max-h-40 overflow-y-auto rounded-xl bg-[#11161f] p-2 font-mono-data text-[11px]">
                          {rsaRes.breakdown.map((row) => (
                            <div key={row.index} className="flex justify-between px-2 py-1 text-[#cbd5e1]">
                              <span>
                                #{row.index} &apos;{row.char}&apos; ({row.byte})
                              </span>
                              <span className="text-[#34d399]">→ {row.cipher}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </Disclosure>
                </div>
              )}
            </div>
          )}

          {algo === 'sha512' && (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
                <h3 className="text-base font-semibold text-white">Digital Fingerprint</h3>
                {shaRes && <StatusPill dark ok passLabel="512-bit SHA-512" />}
              </div>

              {!shaRes ? (
                <DarkEmptyState
                  icon={Fingerprint}
                  title="No fingerprint yet"
                  subtitle="Enter any text on the left to compute its unique SHA-512 fingerprint."
                />
              ) : (
                <div className="space-y-4">
                  <OutputField
                    dark
                    label="Unique Fingerprint (128 hex characters)"
                    value={shaRes.digest_hex}
                  />

                  {shaRes.avalanche && (
                    <div className="rounded-xl bg-[#1a212e] p-3.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[#e2e8f0]">1-Bit Change Test</span>
                        <span className="font-mono-data font-semibold text-[#34d399]">
                          {shaRes.avalanche.diff_pct}% of bits changed ({shaRes.avalanche.diff_bits}/512)
                        </span>
                      </div>
                      <p className="mt-1 text-[#94a3b8]">
                        Changing just 1 tiny bit produces a completely unrecognizable fingerprint.
                      </p>
                    </div>
                  )}

                  <div className="pt-1">
                    <button
                      type="button"
                      onClick={handleShaToQuantum}
                      className="inline-flex items-center gap-2 rounded-xl bg-[#c2410c] px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-[#9a3412]"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      <span>Crack This Fingerprint With Quantum (Grover)</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </div>

                  <Disclosure dark title="Inspect SHA-512 block & padding details">
                    <div className="grid grid-cols-2 gap-2 pt-2 text-xs sm:grid-cols-4">
                      <div>
                        <div className="text-[#64748b]">Input</div>
                        <div className="font-mono-data text-white">{shaRes.input_bytes} B</div>
                      </div>
                      <div>
                        <div className="text-[#64748b]">Zero Pad</div>
                        <div className="font-mono-data text-white">{shaRes.zero_pad_bytes} B</div>
                      </div>
                      <div>
                        <div className="text-[#64748b]">Padded</div>
                        <div className="font-mono-data text-white">{shaRes.padded_bytes} B</div>
                      </div>
                      <div>
                        <div className="text-[#64748b]">Blocks</div>
                        <div className="font-mono-data text-white">{shaRes.block_count} × 128B</div>
                      </div>
                    </div>
                  </Disclosure>
                </div>
              )}
            </div>
          )}

          {algo === 'ecdsa' && (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
                <h3 className="text-base font-semibold text-white">Signature Status</h3>
                {ecdsaRes && ecdsaRes.valid !== undefined && (
                  <StatusPill
                    dark
                    ok={ecdsaRes.valid}
                    passLabel="Authentic · Untampered"
                    failLabel="Tampered · Rejected"
                  />
                )}
              </div>

              {!ecdsaRes ? (
                <DarkEmptyState
                  icon={FileSignature}
                  title="Sign a message to seal it"
                  subtitle="Click Sign Message on the left, then alter a single character and click Verify to catch tampering."
                />
              ) : (
                <div className="space-y-4">
                  {ecdsaRes.valid !== undefined && (
                    <div
                      className={`rounded-xl p-4 text-sm font-medium ${
                        ecdsaRes.valid
                          ? 'bg-[#064e3b]/40 text-[#a7f3d0] ring-1 ring-[#10b981]/30'
                          : 'bg-[#7f1d1d]/40 text-[#fecaca] ring-1 ring-[#ef4444]/30'
                      }`}
                    >
                      {ecdsaRes.valid
                        ? 'This signature matches the exact message and public key.'
                        : 'Warning: This message no longer matches the original signature!'}
                    </div>
                  )}

                  {ecdsaRes.signature && (
                    <OutputField
                      dark
                      label="Digital Signature Seal (r, s)"
                      value={`r: ${ecdsaRes.signature.r}\ns: ${ecdsaRes.signature.s}`}
                    />
                  )}

                  <Disclosure dark title="Inspect public key & message hash">
                    <div className="space-y-3 pt-2">
                      {ecdsaRes.pub && (
                        <OutputField
                          dark
                          label="Public Key Point (NIST P-256)"
                          value={`x: ${ecdsaRes.pub.x}\ny: ${ecdsaRes.pub.y}`}
                        />
                      )}
                      {ecdsaRes.sha512_hex && (
                        <OutputField dark label="Signed Message Hash" value={ecdsaRes.sha512_hex} />
                      )}
                    </div>
                  </Disclosure>
                </div>
              )}
            </div>
          )}

          {algo === 'ecdh' && (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3.5">
                <h3 className="text-base font-semibold text-white">Key Agreement</h3>
                {ecdhRes && (
                  <StatusPill
                    dark
                    ok={ecdhRes.matched}
                    passLabel="Both Computed Same Key"
                    failLabel="Key Mismatch"
                  />
                )}
              </div>

              {!ecdhRes ? (
                <DarkEmptyState
                  icon={Users}
                  title="Simulate a private handshake"
                  subtitle="Click Create Shared Secret on the left to watch Alice and Bob generate an identical secret key."
                />
              ) : (
                <div className="space-y-4">
                  <OutputField
                    dark
                    highlight
                    label="Shared 256-bit Encryption Key (Alice = Bob)"
                    value={ecdhRes.derived_aes_key}
                  />
                  {ecdhRes.encrypted_message_hex && (
                    <OutputField
                      dark
                      label="Message Encrypted With Shared Key"
                      value={ecdhRes.encrypted_message_hex}
                    />
                  )}
                  <Disclosure dark title="Inspect Alice & Bob raw shared secrets">
                    <div className="space-y-3 pt-2">
                      <OutputField dark label="Alice Shared Point X" value={ecdhRes.alice_secret} />
                      <OutputField dark label="Bob Shared Point X" value={ecdhRes.bob_secret} />
                    </div>
                  </Disclosure>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function DarkEmptyState({
  icon: Icon,
  title,
  subtitle,
}: {
  icon: typeof Lock;
  title: string;
  subtitle: string;
}) {
  return (
    <div className="flex min-h-72 flex-col items-center justify-center rounded-xl bg-[#1a212e]/60 p-8 text-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/5 text-[#34d399]">
        <Icon className="h-5 w-5" />
      </div>
      <div className="mt-3 text-sm font-semibold text-white">{title}</div>
      <p className="mt-1 max-w-sm text-xs leading-relaxed text-[#94a3b8]">{subtitle}</p>
    </div>
  );
}
