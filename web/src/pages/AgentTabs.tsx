import { useMemo, useState, type ReactNode } from "react";
import { FileDetails, SigCell, VtCell } from "../components";
import type { Autorun, Command, FileInfo, Finding, Process, Scan, Snapshot } from "../types";
import { ACTION_LABEL, TRIGGER_LABEL, fmtTime, isMicrosoft } from "../util";

/** Envia um comando ao agente (com confirmação). */
export type SendFn = (action: string, params: Record<string, string>, title: string, body: string, danger?: boolean) => void;

export interface TabCtx {
  snap: Snapshot;
  findings: Finding[];
  send: SendFn;
}

// ---------------------------------------------------------------------------
// Ações reutilizáveis

export function QuarantineButton({ f, send }: { f?: FileInfo; send: SendFn }) {
  if (!f?.exists || !f.sha256 || isMicrosoft(f)) return null;
  return (
    <button
      className="btn sm danger"
      onClick={() =>
        send(
          "quarantine_file",
          { path: f.path, sha256: f.sha256! },
          "Mover arquivo para a quarentena?",
          `O arquivo ${f.path} será removido do local original e guardado codificado na quarentena do agente (pode ser restaurado depois). Se estiver em uso, finalize o processo antes.`,
          true,
        )
      }
    >
      Quarentena
    </button>
  );
}

export function DisableAutorunButton({ a, send }: { a: Autorun; send: SendFn }) {
  return (
    <button
      className="btn sm danger"
      onClick={() =>
        send(
          "disable_autorun",
          { autorun_id: a.id },
          "Desativar entrada de inicialização?",
          `"${a.name}" (${a.category}) não será mais executada automaticamente. Um backup é salvo no agente e a ação pode ser desfeita na aba Ações.`,
          true,
        )
      }
    >
      Desativar
    </button>
  );
}

export function KillButton({ p, send }: { p: Process; send: SendFn }) {
  if (!p.image_path) return null;
  return (
    <button
      className="btn sm danger"
      onClick={() =>
        send(
          "kill_process",
          { pid: String(p.pid), image_path: p.image_path! },
          `Finalizar ${p.name} (PID ${p.pid})?`,
          `O processo será encerrado imediatamente. O agente confere se o PID ainda pertence a ${p.image_path} antes de agir.`,
          true,
        )
      }
    >
      Finalizar
    </button>
  );
}

function Filters({ hideMs, setHideMs, q, setQ, extra }: { hideMs: boolean; setHideMs: (v: boolean) => void; q: string; setQ: (v: string) => void; extra?: ReactNode }) {
  return (
    <div className="row" style={{ marginBottom: 12 }}>
      <input type="text" placeholder="Filtrar por nome, caminho, fabricante…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280 }} />
      <label className="check">
        <input type="checkbox" checked={hideMs} onChange={(e) => setHideMs(e.target.checked)} />
        Ocultar itens assinados pela Microsoft
      </label>
      {extra}
    </div>
  );
}

const match = (q: string, ...vals: (string | undefined)[]) => !q || vals.some((v) => v?.toLowerCase().includes(q.toLowerCase()));

// ---------------------------------------------------------------------------
// Inicialização automática (Autoruns)

export function AutorunsTab({ snap, findings, send }: TabCtx) {
  const [hideMs, setHideMs] = useState(true);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const all = snap.report.autoruns ?? [];
  const flagged = useMemo(() => new Set(findings.filter((f) => f.status === "aberto" && f.object_type === "autorun").map((f) => f.object_ref)), [findings]);
  const cats = useMemo(() => [...new Set(all.map((a) => a.category))].sort(), [all]);

  const rows = all
    .filter((a) => !cat || a.category === cat)
    .filter((a) => !hideMs || flagged.has(a.id) || !(isMicrosoft(a.file) && (!a.payload || isMicrosoft(a.payload))))
    .filter((a) => match(q, a.name, a.image_path, a.command, a.file?.signer, a.file?.company, a.location))
    .sort((a, b) => Number(flagged.has(b.id)) - Number(flagged.has(a.id)));

  return (
    <>
      <Filters
        hideMs={hideMs}
        setHideMs={setHideMs}
        q={q}
        setQ={setQ}
        extra={
          <select value={cat} onChange={(e) => setCat(e.target.value)}>
            <option value="">Todas as categorias</option>
            {cats.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        }
      />
      <div className="small muted" style={{ marginBottom: 8 }}>
        {rows.length} de {all.length} entradas. Linhas em vermelho têm achados abertos.
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Entrada</th>
              <th>Executa</th>
              <th>Assinatura / fabricante</th>
              <th>VirusTotal</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} className={`${flagged.has(a.id) ? "hl" : ""} ${a.enabled ? "" : "disabled"}`}>
                <td style={{ maxWidth: 260 }}>
                  <strong className="break">{a.name}</strong>
                  <div className="small muted">
                    {a.category}
                    {!a.enabled && " · desativada"}
                    {a.user && ` · ${a.user}`}
                  </div>
                  <div className="small muted break">{a.location}</div>
                </td>
                <td style={{ maxWidth: 420 }}>
                  <div className="mono break">{a.image_path || a.command}</div>
                  {a.command && a.command !== a.image_path && <div className="small muted mono break">{a.command}</div>}
                  <FileDetails f={a.file} />
                  {a.payload && (
                    <div style={{ marginTop: 6 }}>
                      <div className="small">
                        Arquivo executado: <span className="mono break">{a.payload.path}</span>
                      </div>
                      <SigCell f={a.payload} />
                    </div>
                  )}
                </td>
                <td>
                  <SigCell f={a.file} />
                </td>
                <td>
                  <VtCell f={a.file} hashes={snap.hashes} vtEnabled={snap.intel.vt} />
                  {a.payload && <VtCell f={a.payload} hashes={snap.hashes} vtEnabled={snap.intel.vt} />}
                </td>
                <td>
                  <div className="row">
                    {a.enabled && <DisableAutorunButton a={a} send={send} />}
                    <QuarantineButton f={a.payload ?? a.file} send={send} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Processos

export function ProcessesTab({ snap, findings, send }: TabCtx) {
  const [hideMs, setHideMs] = useState(true);
  const [q, setQ] = useState("");
  const procs = snap.report.processes ?? [];
  const byPid = useMemo(() => new Map(procs.map((p) => [p.pid, p])), [procs]);
  const flagged = useMemo(
    () => new Set(findings.filter((f) => f.status === "aberto" && f.path).map((f) => f.path.toLowerCase())),
    [findings],
  );
  const isFlagged = (p: Process) => !!p.image_path && flagged.has(p.image_path.toLowerCase());

  const rows = procs
    .filter((p) => !hideMs || isFlagged(p) || !isMicrosoft(p.file))
    .filter((p) => match(q, p.name, p.image_path, p.command_line, p.user, p.file?.signer))
    .sort((a, b) => Number(isFlagged(b)) - Number(isFlagged(a)) || a.name.localeCompare(b.name));

  return (
    <>
      <Filters hideMs={hideMs} setHideMs={setHideMs} q={q} setQ={setQ} />
      <div className="small muted" style={{ marginBottom: 8 }}>
        {rows.length} de {procs.length} processos
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>PID</th>
              <th>Processo</th>
              <th>Iniciado por</th>
              <th>Usuário</th>
              <th>Assinatura / fabricante</th>
              <th>VirusTotal</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const parent = byPid.get(p.ppid);
              return (
                <tr key={p.pid} className={isFlagged(p) ? "hl" : ""}>
                  <td className="mono">{p.pid}</td>
                  <td style={{ maxWidth: 460 }}>
                    <strong>{p.name}</strong>
                    {p.image_path && <div className="small mono break">{p.image_path}</div>}
                    {p.command_line && <div className="small muted mono break">{p.command_line}</div>}
                    {p.started && <div className="small muted">desde {fmtTime(p.started)}</div>}
                  </td>
                  <td className="small">
                    {parent ? parent.name : "—"} <span className="muted mono">({p.ppid})</span>
                  </td>
                  <td className="small">{p.user ?? "—"}</td>
                  <td>
                    <SigCell f={p.file} />
                  </td>
                  <td>
                    <VtCell f={p.file} hashes={snap.hashes} vtEnabled={snap.intel.vt} />
                  </td>
                  <td>
                    <div className="row">
                      <KillButton p={p} send={send} />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Rede (netstat -ano)

export function NetworkTab({ snap }: TabCtx) {
  const [onlyEst, setOnlyEst] = useState(true);
  const [q, setQ] = useState("");
  const conns = snap.report.connections ?? [];
  const procs = useMemo(() => new Map((snap.report.processes ?? []).map((p) => [p.pid, p])), [snap]);
  const rows = conns
    .filter((c) => !onlyEst || c.state === "ESTABLISHED" || c.state === "SYN_SENT" || c.state === "LISTENING")
    .filter((c) => match(q, c.remote_addr, c.local_addr, c.process_name, String(c.pid), String(c.remote_port), String(c.local_port)))
    .sort((a, b) => (a.state ?? "").localeCompare(b.state ?? "") || a.pid - b.pid);

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <input type="text" placeholder="Filtrar por IP, porta, processo…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280 }} />
        <label className="check">
          <input type="checkbox" checked={onlyEst} onChange={(e) => setOnlyEst(e.target.checked)} />
          Somente estabelecidas e em escuta
        </label>
        {!snap.intel.abuseipdb && <span className="small muted">Reputação de IPs desativada (configure o AbuseIPDB)</span>}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Proto</th>
              <th>Endereço local</th>
              <th>Endereço remoto</th>
              <th>Estado</th>
              <th>PID / processo</th>
              <th>Reputação do IP remoto</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c, i) => {
              const rep = c.remote_addr ? snap.ips[c.remote_addr] : undefined;
              const p = procs.get(c.pid);
              return (
                <tr key={i} className={rep && rep.score >= 25 ? "hl" : ""}>
                  <td className="mono">{c.proto}</td>
                  <td className="mono">
                    {c.local_addr}:{c.local_port}
                  </td>
                  <td className="mono">{c.remote_addr ? `${c.remote_addr}:${c.remote_port}` : "—"}</td>
                  <td className="small">{c.state ?? "—"}</td>
                  <td>
                    <span className="mono">{c.pid}</span> {c.process_name}
                    {p?.file && !isMicrosoft(p.file) && <SigCell f={p.file} />}
                  </td>
                  <td className="small">
                    {rep?.status === "known" ? (
                      <>
                        <span className={`badge ${rep.score >= 75 ? "sev-critica" : rep.score >= 25 ? "sev-media" : "st-ok"}`}>{rep.score}% abuso</span>{" "}
                        {rep.country} · {rep.isp}
                      </>
                    ) : rep ? (
                      <span className="muted">{rep.status === "pending" ? "na fila" : rep.status}</span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Ações e histórico

const CMD_STATUS: Record<Command["status"], string> = {
  pendente: "Aguardando agente",
  enviado: "Em execução",
  sucesso: "Concluído",
  falha: "Falhou",
  expirado: "Expirado",
};

function paramsText(c: Command) {
  const p = c.params ?? {};
  return p.path || p.image_path || (p.pid ? `PID ${p.pid}` : "") || p.autorun_id || p.backup_id || p.quarantine_id || "";
}

export function ActionsTab({ commands, scans, send, autoruns }: { commands: Command[]; scans: Scan[]; send: SendFn; autoruns: Autorun[] }) {
  const names = new Map(autoruns.map((a) => [a.id, `${a.name} (${a.category})`]));
  return (
    <div className="grid" style={{ gap: 20 }}>
      <div>
        <h3>Ações enviadas</h3>
        {commands.length === 0 ? (
          <div className="muted">Nenhuma ação enviada para este endpoint.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Quando</th>
                  <th>Ação</th>
                  <th>Alvo</th>
                  <th>Situação</th>
                  <th>Resultado</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {commands.map((c) => (
                  <tr key={c.id}>
                    <td className="small">
                      {fmtTime(c.created_at)}
                      <div className="muted">{c.created_by}</div>
                    </td>
                    <td>{ACTION_LABEL[c.action] ?? c.action}</td>
                    <td className="small mono break" style={{ maxWidth: 320 }}>
                      {names.get(c.params?.autorun_id ?? "") ?? paramsText(c)}
                    </td>
                    <td>
                      <span className={`badge st-${c.status}`}>{CMD_STATUS[c.status]}</span>
                    </td>
                    <td className="small break" style={{ maxWidth: 360 }}>
                      {c.result}
                    </td>
                    <td>
                      {c.status === "sucesso" && c.undo_id && c.action === "disable_autorun" && (
                        <button
                          className="btn sm"
                          onClick={() => send("restore_autorun", { backup_id: c.undo_id }, "Restaurar entrada de inicialização?", "A entrada voltará a ser executada automaticamente.")}
                        >
                          Desfazer
                        </button>
                      )}
                      {c.status === "sucesso" && c.undo_id && c.action === "quarantine_file" && (
                        <button
                          className="btn sm"
                          onClick={() => send("restore_file", { quarantine_id: c.undo_id }, "Restaurar arquivo da quarentena?", "O arquivo voltará ao local original. Faça isso apenas se tiver certeza de que é um falso positivo.")}
                        >
                          Restaurar
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div>
        <h3>Histórico de varreduras</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Recebida</th>
                <th>Tipo</th>
                <th>Inicialização</th>
                <th>Processos</th>
                <th>Conexões</th>
                <th>Achados abertos</th>
                <th>Duração</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s, i) => (
                <tr key={i}>
                  <td className="small">{fmtTime(s.received_at)}</td>
                  <td>{TRIGGER_LABEL[s.trigger] ?? s.trigger}</td>
                  <td>{s.autoruns}</td>
                  <td>{s.processes}</td>
                  <td>{s.connections}</td>
                  <td>{s.open_findings}</td>
                  <td className="small">{(s.duration_ms / 1000).toFixed(1)} s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
