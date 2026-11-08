import { api } from "../api";
import type { AuditEntry } from "../types";
import { fmtTime, usePoll } from "../util";

export default function Audit() {
  const { data, error } = usePoll(() => api.get<AuditEntry[]>("/api/audit"), 15000);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Auditoria</h1>
          <div className="muted">Registro de quem fez o quê: logins, comandos enviados e seus resultados</div>
        </div>
      </div>
      {error && <div className="alert crit">{error}</div>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Quando</th>
              <th>Quem</th>
              <th>Ação</th>
              <th>Endpoint</th>
              <th>Detalhe</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((a, i) => (
              <tr key={i}>
                <td className="small">{fmtTime(a.ts)}</td>
                <td className="small mono">{a.actor}</td>
                <td>{a.action.replaceAll("_", " ")}</td>
                <td>{a.agent_id ? <a href={`#/endpoint/${a.agent_id}`}>{a.hostname || a.agent_id}</a> : "—"}</td>
                <td className="small break">{a.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
