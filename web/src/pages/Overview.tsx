import { api } from "../api";
import { SevBadge, StatusBadge } from "../components";
import type { Agent, Overview as OV } from "../types";
import { ago, usePoll } from "../util";

export default function Overview() {
  const ov = usePoll(() => api.get<OV>("/api/overview"), 10000);
  const agents = usePoll(() => api.get<Agent[]>("/api/agents"), 10000);
  const o = ov.data;
  const sev = o?.findings_by_severity ?? {};

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Endpoints</h1>
          <div className="muted">Máquinas monitoradas e situação atual de cada uma</div>
        </div>
      </div>

      <div className="grid kpis">
        <div className="card kpi">
          <div className="l">Endpoints online</div>
          <div className="v">
            {o?.online ?? "–"}
            <span className="muted" style={{ fontSize: 16 }}> / {o?.agents ?? "–"}</span>
          </div>
        </div>
        <div className="card kpi">
          <div className="l">Comprometidos</div>
          <div className="v" style={{ color: o?.status.comprometido ? "var(--crit)" : undefined }}>{o?.status.comprometido ?? 0}</div>
        </div>
        <div className="card kpi">
          <div className="l">Suspeitos</div>
          <div className="v" style={{ color: o?.status.suspeito ? "var(--high)" : undefined }}>{o?.status.suspeito ?? 0}</div>
        </div>
        <div className="card kpi">
          <div className="l">Achados abertos (crít./alta/média)</div>
          <div className="v">
            {sev.critica ?? 0} / {sev.alta ?? 0} / {sev.media ?? 0}
          </div>
        </div>
        <div className="card kpi">
          <div className="l">VirusTotal</div>
          <div className="v" style={{ fontSize: 16, marginTop: 10 }}>
            {o?.intel.vt_enabled ? (
              <>
                {o.intel.hashes_checked} consultados
                <div className="small muted">{o.intel.hashes_pending} na fila</div>
              </>
            ) : (
              <span className="muted">não configurado</span>
            )}
          </div>
        </div>
      </div>

      {agents.error && <div className="alert crit">{agents.error}</div>}
      {agents.data && agents.data.length === 0 && (
        <div className="alert info">
          <strong>Nenhum endpoint cadastrado ainda.</strong>
          Veja em <a href="#/config">Instalação e ajustes</a> o comando para instalar o agente nas máquinas.
        </div>
      )}
      {agents.data && agents.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Máquina</th>
                <th>Situação</th>
                <th>Maior severidade</th>
                <th>Achados</th>
                <th>Última varredura</th>
                <th>Sistema</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {agents.data.map((a) => (
                <tr key={a.id} className="clickable" onClick={() => (window.location.hash = `#/endpoint/${a.id}`)}>
                  <td>
                    <span className={`dot ${a.online ? "on" : ""}`} title={a.online ? "online" : `visto ${ago(a.last_seen)}`} />
                    <strong>{a.hostname}</strong>
                    {a.compromised_at > 0 && (
                      <div className="small" style={{ color: "#fda4af" }}>
                        reinstalação recomendada
                      </div>
                    )}
                  </td>
                  <td>
                    <StatusBadge status={a.status} />
                  </td>
                  <td>
                    <SevBadge sev={a.max_severity} />
                  </td>
                  <td>{a.open_findings}</td>
                  <td>{ago(a.last_report_at)}</td>
                  <td className="small">{a.os}</td>
                  <td className="small mono">{a.remote_ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
