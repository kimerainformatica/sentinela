import { useCallback, useEffect, useRef, useState } from "react";
import type { FileInfo, HostStatus, Severity } from "./types";

export const SEV_LABEL: Record<Severity, string> = {
  critica: "Crítica",
  alta: "Alta",
  media: "Média",
  baixa: "Baixa",
};

export const STATUS_LABEL: Record<HostStatus, string> = {
  comprometido: "Comprometido",
  suspeito: "Suspeito",
  atencao: "Atenção",
  ok: "Sem achados",
  sem_dados: "Aguardando varredura",
};

export const TRIGGER_LABEL: Record<string, string> = {
  inicial: "Inicial",
  agendada: "Agendada",
  manual: "Manual",
  "pos-remediacao": "Verificação pós-remediação",
};

export const ACTION_LABEL: Record<string, string> = {
  rescan: "Nova varredura",
  kill_process: "Finalizar processo",
  disable_autorun: "Desativar inicialização",
  restore_autorun: "Restaurar inicialização",
  quarantine_file: "Quarentena de arquivo",
  restore_file: "Restaurar da quarentena",
};

export function fmtTime(unix: number | string | undefined): string {
  if (!unix) return "—";
  const d = typeof unix === "number" ? new Date(unix * 1000) : new Date(unix);
  if (isNaN(d.getTime()) || d.getFullYear() < 1980) return "—";
  return d.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

export function ago(unix: number): string {
  if (!unix) return "nunca";
  const s = Math.max(0, Date.now() / 1000 - unix);
  if (s < 60) return "agora";
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}

export function fmtSize(n?: number): string {
  if (!n) return "—";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function isMicrosoft(f?: FileInfo): boolean {
  return !!f && f.signature === "valid" && (f.signer ?? "").startsWith("Microsoft");
}

export function vtLink(sha: string) {
  return `https://www.virustotal.com/gui/file/${sha}`;
}

/** Carrega dados e recarrega periodicamente. */
export function usePoll<T>(fn: () => Promise<T>, intervalMs = 10000, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(async () => {
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    setData(null);
    reload();
    const t = window.setInterval(reload, intervalMs);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, reload };
}
