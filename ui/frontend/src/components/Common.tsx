import { ReactNode, useState } from 'react';
import { AlertCircle, Check, ChevronDown, Copy } from 'lucide-react';

export function CopyButton({
  text,
  label = 'Copy',
  dark = false,
}: {
  text: string;
  label?: string;
  dark?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard blocked in restricted browser contexts
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      disabled={!text}
      className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
        dark
          ? 'bg-white/10 text-[#e2e8f0] hover:bg-white/15'
          : 'border border-[#e5e0d6] bg-white text-[#334155] hover:bg-[#f2efe9]'
      }`}
    >
      {copied ? (
        <Check className={`h-3.5 w-3.5 ${dark ? 'text-[#34d399]' : 'text-[#059669]'}`} />
      ) : (
        <Copy className="h-3.5 w-3.5 opacity-75" />
      )}
      <span>{copied ? 'Copied' : label}</span>
    </button>
  );
}

export function StatusPill({
  ok,
  passLabel = 'Verified',
  failLabel = 'Failed',
  dark = false,
}: {
  ok: boolean;
  passLabel?: string;
  failLabel?: string;
  dark?: boolean;
}) {
  if (dark) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${
          ok
            ? 'bg-[#059669]/20 text-[#6ee7b7]'
            : 'bg-[#dc2626]/20 text-[#fca5a5]'
        }`}
      >
        <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-[#34d399]' : 'bg-[#f87171]'}`} />
        {ok ? passLabel : failLabel}
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
        ok ? 'bg-[#ecfdf5] text-[#047857]' : 'bg-[#fef2f2] text-[#b91c1c]'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-[#10b981]' : 'bg-[#ef4444]'}`} />
      {ok ? passLabel : failLabel}
    </span>
  );
}

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-xl bg-[#fef2f2] px-4 py-3 text-sm text-[#991b1b]"
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#dc2626]" />
      <span>{message}</span>
    </div>
  );
}

export function OutputField({
  label,
  value,
  meta,
  mono = true,
  dark = true,
  highlight = false,
}: {
  label: string;
  value: string;
  meta?: string;
  mono?: boolean;
  dark?: boolean;
  highlight?: boolean;
}) {
  if (dark) {
    return (
      <div className="space-y-1.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-[#94a3b8]">{label}</span>
            {meta && <span className="text-xs text-[#64748b] tabular-nums-data">{meta}</span>}
          </div>
          <CopyButton text={value} dark />
        </div>
        <div
          className={`dark-scroll max-h-36 overflow-y-auto break-all rounded-xl px-3.5 py-3 text-xs leading-relaxed ${
            highlight
              ? 'bg-[#064e3b]/40 text-[#a7f3d0] ring-1 ring-[#10b981]/30'
              : 'bg-[#1a212e] text-[#f1f5f9]'
          } ${mono ? 'font-mono-data' : 'text-sm font-medium'}`}
        >
          {value || <span className="text-[#64748b]">—</span>}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-[#4e5665]">{label}</span>
          {meta && <span className="text-xs text-[#767f90] tabular-nums-data">{meta}</span>}
        </div>
        <CopyButton text={value} />
      </div>
      <div
        className={`max-h-36 overflow-y-auto break-all rounded-xl bg-[#f2efe9] px-3.5 py-2.5 text-xs leading-relaxed text-[#141821] ${
          mono ? 'font-mono-data' : 'text-sm'
        }`}
      >
        {value || <span className="text-[#94a3b8]">—</span>}
      </div>
    </div>
  );
}

export function Disclosure({
  title,
  children,
  dark = false,
  defaultOpen = false,
}: {
  title: string;
  children: ReactNode;
  dark?: boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div
      className={`rounded-xl ${
        dark ? 'bg-[#1a212e]/70 text-[#cbd5e1]' : 'bg-[#f5f3ee] text-[#4e5665]'
      }`}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className={`flex w-full items-center justify-between px-3.5 py-2.5 text-left text-xs font-medium transition-colors ${
          dark ? 'text-[#cbd5e1] hover:text-white' : 'text-[#4e5665] hover:text-[#141821]'
        }`}
      >
        <span>{title}</span>
        <ChevronDown
          className={`h-4 w-4 transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
        />
      </button>
      {open && <div className="px-3.5 pb-3.5 pt-0.5">{children}</div>}
    </div>
  );
}

export function StateMatrixGrid({
  title,
  matrix,
}: {
  title: string;
  matrix: string[][];
}) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium text-[#94a3b8]">{title}</div>
      <div className="grid grid-cols-4 gap-1 rounded-lg bg-[#11161f] p-2">
        {matrix.map((row, rIdx) =>
          row.map((cell, cIdx) => (
            <div
              key={`${rIdx}-${cIdx}`}
              className="flex h-7 items-center justify-center rounded bg-[#1e293b] font-mono-data text-[11px] font-medium text-[#e2e8f0]"
            >
              {cell}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function ShotChart({
  counts,
  shots,
  maxRows = 8,
  dark = true,
}: {
  counts: Record<string, number>;
  shots: number;
  maxRows?: number;
  dark?: boolean;
}) {
  const entries = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxRows);
  const maxVal = entries.length > 0 ? Math.max(...entries.map((e) => e[1])) : 1;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-[#94a3b8]">
        <span>Quantum state probabilities</span>
        <span className="tabular-nums-data">{shots.toLocaleString()} simulated runs</span>
      </div>
      <div
        className={`space-y-2 rounded-xl p-3 ${
          dark ? 'bg-[#1a212e]' : 'bg-[#f2efe9]'
        }`}
      >
        {entries.map(([bits, count], idx) => {
          const pct = ((count / shots) * 100).toFixed(1);
          const barWidth = Math.max(3, Math.round((count / maxVal) * 100));
          const isTop = idx === 0 && count > shots * 0.18;
          return (
            <div
              key={bits}
              className="grid grid-cols-[minmax(60px,auto)_1fr_84px] items-center gap-3 text-xs"
            >
              <span
                className={`font-mono-data font-medium ${
                  dark ? 'text-[#e2e8f0]' : 'text-[#141821]'
                }`}
              >
                |{bits.replace(/\s+/g, '')}⟩
              </span>
              <div
                className={`h-2 w-full overflow-hidden rounded-full ${
                  dark ? 'bg-[#0f172a]' : 'bg-[#e5e0d6]'
                }`}
              >
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    isTop ? 'bg-[#f59e0b]' : dark ? 'bg-[#475569]' : 'bg-[#94a3b8]'
                  }`}
                  style={{ width: `${barWidth}%` }}
                />
              </div>
              <span
                className={`text-right font-mono-data ${
                  isTop
                    ? 'font-semibold text-[#fbbf24]'
                    : dark
                    ? 'text-[#94a3b8]'
                    : 'text-[#4e5665]'
                }`}
              >
                {pct}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
