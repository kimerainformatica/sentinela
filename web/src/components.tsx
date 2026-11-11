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
      <FileFlags f={f} />
    </div>
  );
}

/** Nome do arquivo no disco difere do nome original gravado nele? */
function renamed(f: FileInfo): string | null {
  const orig = (f.original_filename ?? "").trim().toLowerCase().replace(/\.mui$/, "");
  if (!orig) return null;
  const disk = (f.path.split("\\").pop() ?? "").toLowerCase();
  const stem = (s: string) => s.replace(/\.[^.]*$/, "");
  const d = stem(disk), o = stem(orig);
  return d === o || d.startsWith(o + "64") || d.startsWith(o + "_") ? null : f.original_filename!;
}

/** Sinais da análise aprofundada: origem, empacotamento, atributos, nome. */
export function FileFlags({ f }: { f?: FileInfo }) {
  if (!f?.exists) return null;
  const flags: { cls: string; text: string; title: string }[] = [];
  if (f.origin && f.origin.zone >= 3)
    flags.push({ cls: "flag-warn", text: "Baixado da " + f.origin.zone_name, title: f.origin.host_url ?? "Mark of the Web (Zone.Identifier)" });
  if (f.pe && !f.pe.is_pe && /\.(exe|dll|scr|sys)$/i.test(f.path))
    flags.push({ cls: "flag-bad", text: "Não é executável", title: "A extensão diz executável, mas o conteúdo não é um programa Windows" });
  if (f.pe?.packed)
    flags.push({ cls: "flag-bad", text: f.pe.packer ? "Empacotado (" + f.pe.packer + ")" : "Código cifrado", title: "Entropia " + f.pe.max_entropy.toFixed(2) + " de 8" });
  if (f.attributes?.includes("oculto")) flags.push({ cls: "flag-warn", text: "Oculto", title: (f.attributes ?? []).join(", ") });
  const r = renamed(f);
  if (r) flags.push({ cls: "flag-warn", text: "Nome original: " + r, title: "Nome gravado no recurso de versão do arquivo" });
  if (!flags.length) return null;
  return (
    <div className="flags">
      {flags.map((x) => (
        <span key={x.text} className={`flag ${x.cls}`} title={x.title}>
          {x.text}
        </span>
      ))}
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
      {f.origin?.host_url && <div className="break">Baixado de {f.origin.host_url}</div>}
      {f.pe?.is_pe && (
        <div>
          Executável {f.pe.machine}
          {f.pe.dll ? " (DLL)" : ""}
          {f.pe.compiled ? ", compilado em " + fmtTime(f.pe.compiled) : ""}, entropia {f.pe.max_entropy.toFixed(2)}
        </div>
      )}
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
