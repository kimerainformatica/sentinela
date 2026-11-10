import { useState } from "react";
import type { Category, LiveEvent, LiveStatus } from "./live";

export const CAT_LABEL: Record<Category, string> = {
  agente: "Agente",
  varredura: "Varredura",
  achado: "Achado",
  inteligencia: "Reputação",
  comando: "Comando",
  painel: "Painel",
};

export const CAT_ICON: Record<Category, string> = {
  agente: "◉",
  varredura: "⟳",
  achado: "⚑",
  inteligencia: "◈",
  comando: "➤",
  painel: "▣",
};

export function fmtClock(ms: number) {
  return new Date(ms).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function agoMs(ms: number) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 5) return "agora";
  if (s < 60) return `há ${s} s`;
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}

export function StatusPill({ status }: { status: LiveStatus }) {
  const txt = { conectado: "Ao vivo", conectando: "Conectando…", reconectando: "Reconectando…" }[status];
  return (
    <span className={`live-pill ${status}`} role="status">
      <span className="pulse" /> {txt}
    </span>
  );
}

function EventRow({ e, showHost, fresh }: { e: LiveEvent; showHost: boolean; fresh: boolean }) {
  const [open, setOpen] = useState(false);
  const hasData = e.data && Object.keys(e.data).length > 0;
  return (
    <li className={`ev lvl-${e.level} ${fresh ? "fresh" : ""}`}>
      <span className="ev-time mono" title={new Date(e.ts).toLocaleString("pt-BR")}>
        {fmtClock(e.ts)}
      </span>
      <span className={`ev-cat cat-${e.category}`}>
        {CAT_ICON[e.category]} {CAT_LABEL[e.category] ?? e.category}
      </span>
      <div className="ev-body">
        {showHost && e.hostname && (
          <a className="ev-host" href={`#/endpoint/${e.agent_id}`}>
            {e.hostname}
          </a>
        )}
        <span className="ev-msg">{e.message}</span>
        {hasData && (
          <button className="ev-more" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? "ocultar" : "detalhes"}
          </button>
        )}
        {open && hasData && <pre className="box mono ev-data">{JSON.stringify(e.data, null, 2)}</pre>}
      </div>
    </li>
  );
}

export function LiveFeed({ events, showHost = true, empty }: { events: LiveEvent[]; showHost?: boolean; empty?: string }) {
  const newest = events[0]?.ts ?? 0;
  if (events.length === 0) return <div className="muted" style={{ padding: 12 }}>{empty ?? "Nenhum evento ainda."}</div>;
  return (
    <ul className="feed">
      {events.map((e) => (
        <EventRow key={e.id} e={e} showHost={showHost} fresh={Date.now() - e.ts < 4000 && e.ts >= newest - 4000} />
      ))}
    </ul>
  );
}
