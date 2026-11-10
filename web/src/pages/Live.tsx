import { useMemo, useState } from "react";
import { api } from "../api";
import { CAT_ICON, CAT_LABEL, LiveFeed, StatusPill, agoMs } from "../LiveFeed";
import { useLiveEvents, useLiveRefresh, useLiveStatus, useTick, type Category, type LiveEvent } from "../live";
import type { Agent, Overview } from "../types";
import { usePoll } from "../util";

const CATS: Category[] = ["agente", "varredura", "achado", "inteligencia", "comando", "painel"];

/** Tela para acompanhar, em tempo real, tudo o que o sistema está fazendo. */
export default function Live() {
  useTick(1000);
  const status = useLiveStatus();
  const [paused, setPaused] = useState(false);
  const [cats, setCats] = useState<Set<Category>>(new Set(CATS));
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  const [agent, setAgent] = useState("");
  const [q, setQ] = useState("");

  const { events, pending, loading } = useLiveEvents({ limit: 500, paused });
  const agents = usePoll(() => api.get<Agent[]>("/api/agents"), 30000);
  const ov = usePoll(() => api.get<Overview>("/api/overview"), 30000);
  useLiveRefresh(
    () => {
      agents.reload();
      ov.reload();
    },
    (e) => e.category !== "painel",
    1500,
  );

  const shown = events.filter(
    (e) =>
      cats.has(e.category) &&
      (!onlyAlerts || e.level === "alerta" || e.level === "critico") &&
      (!agent || e.agent_id === agent) &&
      (!q || e.message.toLowerCase().includes(q.toLowerCase()) || (e.hostname ?? "").toLowerCase().includes(q.toLowerCase())),
  );

  // Último evento de cada máquina = o que ela está fazendo agora
  const lastByAgent = useMemo(() => {
    const m = new Map<string, LiveEvent>();
    for (const e of events) if (e.agent_id && !m.has(e.agent_id)) m.set(e.agent_id, e);
    return m;
  }, [events]);

  const now = Date.now();
  const last5min = events.filter((e) => now - e.ts < 5 * 60_000);
  const alerts5min = last5min.filter((e) => e.level === "alerta" || e.level === "critico").length;
  const o = ov.data;

  const toggleCat = (c: Category) =>
    setCats((prev) => {
      const n = new Set(prev);
      if (n.has(c)) n.delete(c);
      else n.add(c);
      return n.size ? n : new Set(CATS);
    });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>
            Ao vivo <StatusPill status={status} />
          </h1>
          <div className="muted">Tudo o que os agentes e o servidor estão fazendo, no momento em que acontece</div>
        </div>
        <button className={`btn ${paused ? "primary" : ""}`} onClick={() => setPaused(!paused)}>
          {paused ? `Retomar${pending ? ` (${pending} novos)` : ""}` : "Pausar"}
        </button>
      </div>

      <div className="grid kpis">
        <div className="card kpi">
          <div className="l">Agentes online</div>
          <div className="v">
            {o?.online ?? "–"}
            <span className="muted" style={{ fontSize: 16 }}> / {o?.agents ?? "–"}</span>
          </div>
        </div>
        <div className="card kpi">
          <div className="l">Eventos nos últimos 5 min</div>
          <div className="v">{last5min.length}</div>
        </div>
        <div className="card kpi">
          <div className="l">Alertas nos últimos 5 min</div>
          <div className="v" style={{ color: alerts5min ? "var(--high)" : undefined }}>{alerts5min}</div>
        </div>
        <div className="card kpi">
          <div className="l">Fila do VirusTotal</div>
          <div className="v" style={{ fontSize: o?.intel.vt_enabled ? undefined : 16, marginTop: o?.intel.vt_enabled ? undefined : 10 }}>
            {o?.intel.vt_enabled ? o.intel.hashes_pending : <span className="muted">desativado</span>}
          </div>
        </div>
      </div>

      <div className="live-grid">
        <section>
          <div className="row" style={{ marginBottom: 10 }}>
            {CATS.map((c) => (
              <button key={c} className={`chip cat-${c} ${cats.has(c) ? "on" : ""}`} onClick={() => toggleCat(c)} aria-pressed={cats.has(c)}>
                {CAT_ICON[c]} {CAT_LABEL[c]}
              </button>
            ))}
          </div>
          <div className="row" style={{ marginBottom: 12 }}>
            <input type="text" placeholder="Buscar nos eventos…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 240 }} />
            <select value={agent} onChange={(e) => setAgent(e.target.value)}>
              <option value="">Todos os endpoints</option>
              {agents.data?.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
            <label className="check">
              <input type="checkbox" checked={onlyAlerts} onChange={(e) => setOnlyAlerts(e.target.checked)} />
              Só alertas e críticos
            </label>
            <span className="small muted">
              {shown.length} de {events.length} eventos
            </span>
          </div>
          <div className="card" style={{ padding: 0 }}>
            {loading && events.length === 0 ? (
              <div className="muted" style={{ padding: 12 }}>
                Carregando…
              </div>
            ) : (
              <LiveFeed
                events={shown}
                empty="Nenhum evento com esses filtros. Inicie um agente (veja ao lado) para ver a atividade aparecer aqui."
              />
            )}
          </div>
        </section>

        <aside>
          <h3>O que cada máquina está fazendo</h3>
          <div className="list">
            {agents.data?.length === 0 && (
              <div className="card small muted">
                Nenhum agente ainda. Para ver um agente real funcionando nesta máquina, rode o modo dev mostrado em{" "}
                <a href="#/config">Instalação e ajustes</a>.
              </div>
            )}
            {agents.data?.map((a) => {
              const le = lastByAgent.get(a.id);
              return (
                <a key={a.id} className="card agent-now" href={`#/endpoint/${a.id}`}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <strong>
                      <span className={`dot ${a.online ? "on" : ""}`} />
                      {a.hostname}
                    </strong>
                    <span className={`badge st-${a.status}`}>{a.open_findings} achados</span>
                  </div>
                  {le ? (
                    <div className={`small now-msg lvl-${le.level}`}>
                      {le.message}
                      <div className="muted">{agoMs(le.ts)}</div>
                    </div>
                  ) : (
                    <div className="small muted">sem atividade recente</div>
                  )}
                </a>
              );
            })}
          </div>
        </aside>
      </div>
    </>
  );
}
