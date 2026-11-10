import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export type Category = "agente" | "processo" | "varredura" | "achado" | "inteligencia" | "comando" | "painel";
export type Level = "info" | "ok" | "alerta" | "critico";

export interface LiveEvent {
  id: number;
  ts: number; // ms
  category: Category;
  kind: string;
  level: Level;
  agent_id?: string;
  hostname?: string;
  message: string;
  data?: Record<string, unknown>;
}

export type LiveStatus = "conectando" | "conectado" | "reconectando";

// Uma única conexão SSE compartilhada por todas as telas.
let es: EventSource | null = null;
let retryTimer: number | undefined;
let status: LiveStatus = "conectando";
const listeners = new Set<(e: LiveEvent) => void>();
const statusListeners = new Set<(s: LiveStatus) => void>();

function setStatus(s: LiveStatus) {
  status = s;
  statusListeners.forEach((l) => l(s));
}

function connect() {
  if (es) return;
  es = new EventSource("/api/events/stream");
  es.onopen = () => setStatus("conectado");
  es.onmessage = (m) => {
    try {
      const e = JSON.parse(m.data) as LiveEvent;
      listeners.forEach((l) => l(e));
    } catch {
      /* ignora mensagem malformada */
    }
  };
  es.onerror = () => {
    setStatus("reconectando");
    // Erro HTTP (ex.: sessão expirada) fecha o EventSource de vez: recria.
    if (es && es.readyState === EventSource.CLOSED) {
      es = null;
      window.clearTimeout(retryTimer);
      retryTimer = window.setTimeout(() => {
        api.get("/api/me").then(connect, () => {}); // 401 leva ao login
      }, 5000);
    }
  };
}

export function closeLive() {
  es?.close();
  es = null;
  window.clearTimeout(retryTimer);
  setStatus("conectando");
}

export function subscribe(fn: (e: LiveEvent) => void) {
  connect();
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function useLiveStatus() {
  const [s, setS] = useState<LiveStatus>(status);
  useEffect(() => {
    connect();
    statusListeners.add(setS);
    setS(status);
    return () => {
      statusListeners.delete(setS);
    };
  }, []);
  return s;
}

/** Histórico + eventos novos em tempo real (mais recentes primeiro). */
export function useLiveEvents(opts: { agent?: string; limit?: number; paused?: boolean } = {}) {
  const limit = opts.limit ?? 300;
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [pending, setPending] = useState<LiveEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const pausedRef = useRef(!!opts.paused);
  pausedRef.current = !!opts.paused;

  useEffect(() => {
    let alive = true;
    const seen = new Set<number>();
    setEvents([]);
    setPending([]);
    setLoading(true);

    const unsub = subscribe((e) => {
      if (opts.agent && e.agent_id !== opts.agent) return;
      if (seen.has(e.id)) return;
      seen.add(e.id);
      if (pausedRef.current) {
        setPending((p) => [e, ...p].slice(0, limit));
      } else {
        setEvents((prev) => [e, ...prev].slice(0, limit));
      }
    });

    const q = new URLSearchParams({ limit: String(Math.min(limit, 500)) });
    if (opts.agent) q.set("agent", opts.agent);
    api
      .get<LiveEvent[]>(`/api/events?${q}`)
      .then((hist) => {
        if (!alive) return;
        hist.forEach((e) => seen.add(e.id));
        // eventos que chegaram ao vivo durante o carregamento ficam no topo
        setEvents((prev) => {
          const ids = new Set(prev.map((e) => e.id));
          return [...prev, ...hist.filter((e) => !ids.has(e.id))].sort((a, b) => b.id - a.id).slice(0, limit);
        });
      })
      .finally(() => alive && setLoading(false));

    return () => {
      alive = false;
      unsub();
    };
  }, [opts.agent, limit]);

  // Ao retomar, aplica o que chegou enquanto estava pausado.
  useEffect(() => {
    if (!opts.paused && pending.length) {
      setEvents((prev) => [...pending, ...prev].slice(0, limit));
      setPending([]);
    }
  }, [opts.paused, pending, limit]);

  return { events, pending: pending.length, loading };
}

/** Chama reload (com debounce) quando chega um evento relevante. */
export function useLiveRefresh(reload: () => void, match: (e: LiveEvent) => boolean, delayMs = 700) {
  const reloadRef = useRef(reload);
  const matchRef = useRef(match);
  reloadRef.current = reload;
  matchRef.current = match;
  useEffect(() => {
    let t: number | undefined;
    const unsub = subscribe((e) => {
      if (!matchRef.current(e)) return;
      window.clearTimeout(t);
      t = window.setTimeout(() => reloadRef.current(), delayMs);
    });
    return () => {
      unsub();
      window.clearTimeout(t);
    };
  }, [delayMs]);
}

/** Força re-render periódico (para "há 5 s" atualizar sozinho). */
export function useTick(ms = 1000) {
  const [, set] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => set((n) => n + 1), ms);
    return () => window.clearInterval(t);
  }, [ms]);
}
