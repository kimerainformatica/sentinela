import { createContext, useContext, useState, type ReactNode } from "react";
import type { FileInfo, HashRep, HostStatus, Severity } from "./types";
import { SEV_LABEL, STATUS_LABEL, fmtTime, vtLink } from "./util";

export function SevBadge({ sev }: { sev: Severity | "" }) {
  if (!sev) return <span className="badge st-ok">Nenhum</span>;
  return <span className={`badge sev-${sev}`}>{SEV_LABEL[sev]}</span>;
}

export function StatusBadge({ status }: { status: HostStatus }) {
  return <span className={`badge st-${status}`}>{STATUS_LABEL[status]}</span>;
}

const SIG_LABEL: Record<string, string> = {
  valid: "Assinado",
  unsigned: "Sem assinatura",
  invalid: "Assinatura inválida",
  error: "Não verificado",
};

/** Assinatura digital + fabricante, como as colunas Publisher/Verified do Autoruns. */
export function SigCell({ f }: { f?: FileInfo }) {
  if (!f) return <span className="muted">—</span>;
  if (!f.exists) return <span className="badge st-expirado">{f.error ? "Sem acesso" : "Arquivo não existe"}</span>;
  const sig = f.signature ?? "error";
  return (
    <div>
      <span className={`badge sig-${sig}`} title={f.error}>
        {SIG_LABEL[sig]}
      </span>
      {f.signer && <div className="small">{f.signer}</div>}
      {f.company && f.company !== f.signer && <div className="small muted">Fabricante: {f.company}</div>}
    </div>
  );
}

/** Resultado da consulta de reputação no VirusTotal. */
export function VtCell({ f, hashes, vtEnabled }: { f?: FileInfo; hashes: Record<string, HashRep>; vtEnabled: boolean }) {
  if (!f?.sha256) return <span className="muted">—</span>;
  const r = hashes[f.sha256];
  const link = (
    <a href={vtLink(f.sha256)} target="_blank" rel="noreferrer noopener" className="small">
      abrir ↗
    </a>
  );
  if (!r) {
    return <div className="small muted">{vtEnabled ? "não consultado" : "VT desativado"} · {link}</div>;
  }
  switch (r.status) {
    case "pending":
      return <div className="small muted">na fila · {link}</div>;
    case "unknown":
      return <div className="small muted">desconhecido · {link}</div>;
    case "error":
      return <div className="small muted">erro · {link}</div>;
  }
  const cls = r.malicious >= 5 ? "sev-critica" : r.malicious >= 2 ? "sev-alta" : r.malicious === 1 ? "sev-media" : "st-ok";
  return (
    <div>
      <span className={`badge ${cls}`} title={r.label}>
        {r.malicious}/{r.total}
      </span>{" "}
      {link}
      {r.label && <div className="small muted">{r.label}</div>}
    </div>
  );
}

export function FileDetails({ f }: { f?: FileInfo }) {
  if (!f) return null;
  return (
    <div className="small muted">
      {f.description && <div>{f.description}</div>}
      {f.created && <div>Criado em {fmtTime(f.created)}</div>}
      {f.sha256 && <div className="mono break">SHA-256 {f.sha256}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal de confirmação

export interface ConfirmSpec {
  title: string;
  body: ReactNode;
  confirm: string;
  danger?: boolean;
  onConfirm: () => Promise<void> | void;
}

export function ConfirmModal({ spec, onClose }: { spec: ConfirmSpec | null; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  if (!spec) return null;
  return (
    <div className="modal-bg" onClick={() => !busy && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <h2>{spec.title}</h2>
        <div>{spec.body}</div>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 16 }}>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button
            className={`btn ${spec.danger ? "danger" : "primary"}`}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await spec.onConfirm();
                onClose();
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Enviando…" : spec.confirm}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Notificações

const ToastCtx = createContext<(msg: string, err?: boolean) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [t, setT] = useState<{ msg: string; err: boolean } | null>(null);
  const show = (msg: string, err = false) => {
    setT({ msg, err });
    window.setTimeout(() => setT(null), 5000);
  };
  return (
    <ToastCtx.Provider value={show}>
      {children}
      {t && (
        <div className={`toast ${t.err ? "err" : ""}`} role="status">
          {t.msg}
        </div>
      )}
    </ToastCtx.Provider>
  );
}
