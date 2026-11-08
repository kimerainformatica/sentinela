import { useState, type ReactNode } from "react";
import { api } from "../api";
import { SevBadge, useToast } from "../components";
import type { Finding } from "../types";
import { fmtTime, usePoll, vtLink } from "../util";

const STATUS_TXT: Record<Finding["status"], string> = {
  aberto: "Aberto",
  resolvido: "Resolvido",
  falso_positivo: "Falso positivo",
};

export function FindingCard({ f, showHost, actions, onChange }: { f: Finding; showHost?: boolean; actions?: ReactNode; onChange?: () => void }) {
  const toast = useToast();
  const setStatus = async (status: string) => {
    try {
      await api.post(`/api/findings/${f.id}/status`, { status });
      onChange?.();
    } catch (e) {
      toast((e as Error).message, true);
    }
  };
  return (
    <div className={`card finding ${f.severity}`}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="row">
          <SevBadge sev={f.severity} />
          <span className={`badge st-${f.status}`}>{STATUS_TXT[f.status]}</span>
          {showHost && <a href={`#/endpoint/${f.agent_id}`}>{f.hostname}</a>}
          <span className="small muted">
            {f.rule_id}
            {f.technique && (
              <>
                {" · "}
                <a href={`https://attack.mitre.org/techniques/${f.technique.replace(".", "/")}/`} target="_blank" rel="noreferrer noopener">
                  ATT&CK {f.technique}
                </a>
              </>
            )}
          </span>
        </div>
        <span className="small muted">
          visto em {fmtTime(f.first_seen)}
          {f.status === "resolvido" && ` · resolvido em ${fmtTime(f.resolved_at)}`}
        </span>
      </div>
      <div className="title">{f.title}</div>
      <div className="detail break">{f.detail}</div>
      {f.sha256 && (
        <div className="small" style={{ marginTop: 6 }}>
          <a href={vtLink(f.sha256)} target="_blank" rel="noreferrer noopener">
            Ver no VirusTotal ↗
          </a>
        </div>
      )}
      <div className="row" style={{ marginTop: 10 }}>
        {actions}
        {f.status === "aberto" && (
          <button className="btn sm" onClick={() => setStatus("falso_positivo")}>
            Marcar como falso positivo
          </button>
        )}
        {f.status === "falso_positivo" && (
          <button className="btn sm" onClick={() => setStatus("aberto")}>
            Reabrir
          </button>
        )}
      </div>
    </div>
  );
}

export default function Findings() {
  const [status, setStatus] = useState("aberto");
  const { data, error, reload } = usePoll(() => api.get<Finding[]>(`/api/findings?status=${status}`), 15000, [status]);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Achados</h1>
          <div className="muted">Detecções de todos os endpoints, das mais graves para as menos graves</div>
        </div>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="aberto">Abertos</option>
          <option value="resolvido">Resolvidos</option>
          <option value="falso_positivo">Falsos positivos</option>
          <option value="todos">Todos</option>
        </select>
      </div>
      {error && <div className="alert crit">{error}</div>}
      {data && data.length === 0 && <div className="alert info">Nenhum achado nesta categoria.</div>}
      <div className="list">
        {data?.map((f) => (
          <FindingCard key={f.id} f={f} showHost onChange={reload} />
        ))}
      </div>
    </>
  );
}
