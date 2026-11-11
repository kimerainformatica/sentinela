import { useState } from "react";
import { api } from "../api";
import type { LiveEvent } from "../live";
import type { FloodBlock } from "../types";
import { fmtTime, usePoll } from "../util";
import type { SendFn } from "./AgentTabs";

function expiresIn(unix: number): string {
  const s = Math.round(unix - Date.now() / 1000);
  if (s <= 0) return "expirando";
  if (s < 3600) return `${Math.ceil(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

/** Proteção contra DDoS: resposta automática e bloqueios de firewall. */
export function ProtectionTab({ agentId, send }: { agentId: string; send: SendFn }) {
  const blocks = usePoll(() => api.get<FloodBlock[]>(`/api/agents/${agentId}/blocks`), 10000, [agentId]);
  const prot = usePoll(() => api.get<LiveEvent[]>(`/api/events?agent=${agentId}&kind=protection&limit=1`), 15000, [agentId]);
  const [ip, setIp] = useState("");
  const [min, setMin] = useState("60");

  const protEvent = prot.data?.[0];
  const on = protEvent?.data?.protect;
  const known = typeof on === "boolean";

  const toggle = (enabled: boolean) =>
    send(
      "set_protection",
      { enabled: enabled ? "1" : "0" },
      enabled ? "Ligar resposta automática a DDoS?" : "Desligar resposta automática a DDoS?",
      enabled
        ? "O agente passará a finalizar sozinho o processo que estiver atacando (saída) e a bloquear os IPs que estiverem atacando a máquina (entrada)."
        : "Os ataques continuarão sendo detectados e alertados, mas o agente NÃO vai mais finalizar processos nem bloquear IPs sozinho. Use se a resposta automática estiver atrapalhando.",
      !enabled,
    );

  const manualBlock = () => {
    send(
      "block_ip",
      min ? { ip, minutes: min, reason: "manual" } : { ip, reason: "manual" },
      `Bloquear ${ip} no firewall?`,
      `A máquina deixará de aceitar conexões de ${ip} por ${min || "60"} minutos. O bloqueio pode ser removido aqui a qualquer momento.`,
      true,
    );
    setIp("");
  };

  return (
    <div className="grid" style={{ gap: 22 }}>
      <div>
        <h3>Resposta automática</h3>
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div>
                Estado:{" "}
                {known ? (
                  <strong style={{ color: on ? "var(--ok)" : "var(--high)" }}>{on ? "LIGADA" : "DESLIGADA"}</strong>
                ) : (
                  <span className="muted">desconhecido (o agente informa ao iniciar; atualize após a próxima verificação)</span>
                )}
              </div>
              <div className="small muted" style={{ marginTop: 4 }}>
                Quando ligada, o agente finaliza o processo que está gerando um DDoS (saída) e bloqueia no firewall os IPs que
                inundam a máquina (entrada), no instante em que detecta — sem esperar um analista. Processos críticos do Windows e o
                IP do servidor nunca são afetados.
              </div>
            </div>
            <div className="row">
              <button className="btn sm" disabled={known && on === true} onClick={() => toggle(true)}>
                Ligar
              </button>
              <button className="btn sm danger" disabled={known && on === false} onClick={() => toggle(false)}>
                Desligar
              </button>
            </div>
          </div>
        </div>
      </div>

      <div>
        <h3>IPs bloqueados no firewall</h3>
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="row" style={{ alignItems: "flex-end", gap: 10 }}>
            <label className="small">
              IP de origem
              <input type="text" placeholder="203.0.113.5" value={ip} onChange={(e) => setIp(e.target.value)} style={{ display: "block", minWidth: 200 }} />
            </label>
            <label className="small">
              Minutos
              <input type="number" min={1} value={min} onChange={(e) => setMin(e.target.value)} style={{ display: "block", width: 90 }} />
            </label>
            <button className="btn sm danger" disabled={!ip.trim()} onClick={manualBlock}>
              Bloquear
            </button>
          </div>
        </div>
        {blocks.data && blocks.data.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Motivo</th>
                  <th>Bloqueado em</th>
                  <th>Expira em</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {blocks.data.map((b) => (
                  <tr key={b.ip}>
                    <td className="mono">{b.ip}</td>
                    <td className="small">{b.reason || "—"}</td>
                    <td className="small">{fmtTime(b.created)}</td>
                    <td className="small">{b.expires ? expiresIn(b.expires) : "—"}</td>
                    <td>
                      <button
                        className="btn sm"
                        onClick={() =>
                          send("unblock_ip", { ip: b.ip }, `Desbloquear ${b.ip}?`, "A máquina voltará a aceitar conexões desse IP.")
                        }
                      >
                        Desbloquear
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="muted">Nenhum IP bloqueado.</div>
        )}
      </div>
    </div>
  );
}
