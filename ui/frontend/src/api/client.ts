export type ModeTab = 'classical' | 'quantum' | 'tests';
export type ClassicalAlgorithm = 'aes256' | 'rsa' | 'sha512' | 'ecdsa' | 'ecdh';
export type QuantumAlgorithm = 'shor_rsa' | 'shor_ecc' | 'grover_aes' | 'grover_sha512';

export interface HealthResponse {
  ok: boolean;
  cpp_ready: boolean;
  binaries: Record<string, boolean>;
  qiskit_version: string;
  toy_ecc: {
    p: number;
    a: number;
    b: number;
    G: [number, number];
    order: number;
    total_points: number;
    subgroup: { k: number; point: [number, number] }[];
  };
}

export interface AES256Response {
  ok: boolean;
  action: 'encrypt' | 'decrypt';
  padding: 'pkcs7' | 'none';
  key_hex: string;
  key_source: string;
  output_hex: string;
  recovered_text?: string;
  padding_valid?: boolean;
  elapsed_ms: number;
  blocks: {
    index: number;
    input_hex: string;
    output_hex: string;
    input_state: string[][];
    output_state: string[][];
  }[];
}

export interface RSAResponse {
  ok: boolean;
  action: string;
  keys: { p: number; q: number; n: number; phi: number; e: number; d: number };
  ciphertext_ints?: number[];
  ciphertext_str?: string;
  recovered_text?: string;
  input_number?: number;
  result?: number;
  elapsed_ms: number;
  breakdown?: {
    index: number;
    byte: number;
    hex: string;
    char: string;
    cipher: number;
  }[];
}

export interface SHA512Response {
  ok: boolean;
  action: string;
  digest_hex: string;
  input_bytes: number;
  padded_bytes: number;
  zero_pad_bytes: number;
  block_count: number;
  bit_length: number;
  elapsed_ms: number;
  avalanche?: {
    modified_hex: string;
    modified_text: string;
    modified_digest_hex: string;
    diff_bits: number;
    total_bits: number;
    diff_pct: number;
  };
}

export interface ECDSAResponse {
  ok: boolean;
  action: 'keygen' | 'sign' | 'verify';
  priv_hex?: string;
  pub?: { x: string; y: string };
  sha512_hex?: string;
  digest_e?: string;
  signature?: { r: string; s: string };
  on_curve?: boolean;
  valid?: boolean;
  elapsed_ms: number;
}

export interface ECDHResponse {
  ok: boolean;
  action: 'ecdh';
  alice_priv: string;
  alice_pub: { x: string; y: string };
  bob_priv: string;
  bob_pub: { x: string; y: string };
  alice_secret: string;
  bob_secret: string;
  matched: boolean;
  derived_aes_key: string;
  encrypted_message_hex?: string;
  elapsed_ms: number;
}

export interface ShorRSAResponse {
  ok: boolean;
  algorithm: 'shor_rsa';
  N: number;
  e: number;
  a: number;
  n_count: number;
  n_target: number;
  n_qubits: number;
  shots: number;
  input_mode: 'number' | 'text';
  chunk_mode: string | null;
  normalized_message: number | null;
  target_ciphertexts: number[];
  counts: Record<string, number>;
  phase_observations: {
    bits: string;
    measured: number;
    phase: number;
    r_estimate: number;
    verified_period: number | null;
    count: number;
  }[];
  candidate_periods: number[];
  used_period: number | null;
  factors: number[];
  recovered_phi: number | null;
  recovered_d: number | null;
  decrypted_values: number[];
  recovered_text: string | null;
  factorization_check: boolean;
  verified: boolean;
  elapsed_ms: number;
}

export interface ShorECCResponse {
  ok: boolean;
  algorithm: 'shor_ecc';
  curve: { p: number; a: number; b: number; G: [number, number]; order: number };
  Q: [number, number];
  reference_d: number | null;
  n_qubits: number;
  shots: number;
  joint_counts: Record<string, number>;
  uv_samples: {
    bitstring: string;
    u: number;
    v: number;
    u_invertible: boolean;
    candidate_d: number | null;
    count: number;
  }[];
  candidates: Record<string, number>;
  recovered_d: number | null;
  verified: boolean;
  elapsed_ms: number;
}

export interface GroverAESResponse {
  ok: boolean;
  algorithm: 'grover_aes';
  n_bits: number;
  n_qubits: number;
  search_space: number;
  shots: number;
  iterations: number;
  plaintext_hex: string;
  plaintext_note: string;
  target_ciphertext_hex: string;
  marked_states: number[];
  counts: Record<string, number>;
  recovered_k: number;
  recovered_bits: string;
  recovered_key_hex: string;
  decrypted_hex: string;
  decrypted_text: string;
  top_probability_pct: number;
  verified: boolean;
  elapsed_ms: number;
}

export interface GroverSHA512Response {
  ok: boolean;
  algorithm: 'grover_sha512';
  n_bits: number;
  n_qubits: number;
  search_space: number;
  suffix_mode: 'raw_byte' | 'decimal_ascii' | 'hex_char';
  prefix: string;
  shots: number;
  iterations: number;
  target_digest_hex: string;
  marked_states: number[];
  counts: Record<string, number>;
  recovered_k: number;
  recovered_bits: string;
  recovered_message_repr: string;
  recovered_message_text: string;
  recovered_message_hex: string;
  recovered_digest_hex: string;
  top_probability_pct: number;
  verified: boolean;
  elapsed_ms: number;
}

export interface TestSuiteResponse {
  ok: boolean;
  suite: string;
  results: {
    id: string;
    title: string;
    language: string;
    passed: boolean;
    elapsed_ms: number;
    output: string;
  }[];
}

export interface QuantumHandoff {
  algorithm: QuantumAlgorithm;
  sourceLabel?: string;
  // Shor RSA
  rsaN?: number;
  rsaE?: number;
  rsaCiphertexts?: number[];
  rsaTextMode?: boolean;
  rsaTextInput?: string;
  // Shor ECC
  eccPoint?: [number, number];
  // Grover AES
  aesPlaintext?: string;
  aesCiphertextHex?: string;
  // Grover SHA-512
  shaPrefix?: string;
  shaSuffixMode?: 'raw_byte' | 'decimal_ascii' | 'hex_char';
  shaDigestHex?: string;
  shaN?: number;
  shaCandidates?: string[];
  shaOriginalText?: string;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return data as T;
}

export const api = {
  health: async (): Promise<HealthResponse> => {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error('Backend health check failed');
    return res.json();
  },
  aes256: (body: unknown) => postJson<AES256Response>('/api/classical/aes256', body),
  rsa: (body: unknown) => postJson<RSAResponse>('/api/classical/rsa', body),
  sha512: (body: unknown) => postJson<SHA512Response>('/api/classical/sha512', body),
  ecdsa: (body: unknown) => postJson<ECDSAResponse>('/api/classical/ecc/ecdsa', body),
  ecdh: (body: unknown) => postJson<ECDHResponse>('/api/classical/ecc/ecdh', body),
  shorRsa: (body: unknown) => postJson<ShorRSAResponse>('/api/quantum/shor-rsa', body),
  shorEcc: (body: unknown) => postJson<ShorECCResponse>('/api/quantum/shor-ecc', body),
  groverAes: (body: unknown) => postJson<GroverAESResponse>('/api/quantum/grover-aes', body),
  groverSha512: (body: unknown) => postJson<GroverSHA512Response>('/api/quantum/grover-sha512', body),
  runTests: (suite: string) => postJson<TestSuiteResponse>('/api/tests/run', { suite }),
};
