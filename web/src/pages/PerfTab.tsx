import { api } from "../api";
import type { LiveEvent } from "../live";
import type { AgentPerf, InspectPerf, ScanPerf } from "../types";
import { fmtTime, usePoll } from "../util";

const OP_LABEL: Record<string, [string, string]> = {
  metadados: ["Metadados", "Tamanho, datas e atributos; também decide se o cache ainda vale"],
  sha256: ["SHA-256", "Lê o arquivo inteiro para calcular o hash usado no VirusTotal"],
  versao: ["Recurso de versão", "Fabricante, produto, descrição e nome original"],
  assinatura: ["Assinatura embutida", "Verificação Authenticode pelo Windows (WinVerifyTrust)"],
  catalogo: ["Catálogo do Windows", "Busca o arquivo nos catálogos do sistema quando não há assinatura embutida"],
  assinante: ["Assinante", "Extrai o nome de quem assinou"],
  pe: ["Estrutura do executável", "Cabeçalho, seções e entropia (só arquivos sem assinatura válida)"],
  origem: ["Origem do download", "Lê o Mark of the Web (Zone.Identifier)"],
};
const OP_ORDER = Object.keys(OP_LABEL);

const PHASE_LABEL: Record<string, string> = {
  inicializacao: "Inicialização automática",
  processos: "Processos",
  rede: "Conexões de rede",
};

const ms = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${v.toFixed(v < 10 ? 1 : 0)} ms`);
const mb = (b?: number) => (b ? `${(b / (1 << 20)).toFixed(0)} MB` : "");

function hitRate(p: InspectPerf) {
  return p.lookups ? Math.round((100 * p.cache_hits) / p.lookups) : 0;
}

function OpsTable({ p }: { p: InspectPerf }) {
  const total = Object.values(p.ops ?? {}).reduce((a, c) => a + c.ms, 0);
  const rows = OP_ORDER.filter((k) => p.ops?.[k]);
  if (!rows.length) return <div className="small muted">Nenhum arquivo precisou ser analisado: tudo veio do cache.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Operação</th>
            <th className="num">Vezes</th>
            <th className="num">Total</th>
            <th className="num">Média</th>
            <th style={{ width: "28%" }}>Parcela do tempo</th>
            <th className="num">Dados lidos</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((k) => {
            const c = p.ops[k];
            const pct = total ? (100 * c.ms) / total : 0;
            return (
              <tr key={k}>
                <td>
                  {OP_LABEL[k][0]}
                  <div className="small muted">{OP_LABEL[k][1]}</div>
                </td>
                <td className="num">{c.count}</td>
                <td className="num">{ms(c.ms)}</td>
                <td className="num">{ms(c.ms / c.count)}</td>
                <td>
                  <div className="meter" aria-label={`${pct.toFixed(0)}%`}>
                    <span style={{ width: `${pct}%` }} />
                  </div>
                  <span className="small muted">{pct.toFixed(0)}%</span>
                </td>
                <td className="num small">
                  {mb(c.bytes)}
                  {c.bytes ? <div className="muted">{(c.bytes / (1 << 20) / Math.max(c.ms / 1000, 0.001)).toFixed(0)} MB/s</div> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Slowest({ p }: { p: InspectPerf }) {
  const list = (p.slowest ?? []).filter((f) => f.ms >= 1);
  if (!list.length) return null;
  return (
    <>
      <h3>Arquivos mais demorados</h3>
      <div className="card" style={{ padding: 0 }}>
        <ul className="feed">
          {list.map((f) => (
            <li key={f.path} className="ev">
              <span className="ev-time mono">{ms(f.ms)}</span>
              <span className="mono small break">{f.path}</span>
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

function ScanSection({ perf, when }: { perf?: ScanPerf; when?: string }) {
  if (!perf)
    return <div className="card small muted">A última varredura foi feita por uma versão do agente que ainda não media o custo.</div>;
  const analyzed = perf.inspect.lookups - perf.inspect.cache_hits;
  return (
    <>
      <div className="grid kpis">
        <div className="card kpi">
          <div className="l">Duração da varredura</div>
          <div className="v">{ms(perf.wall_ms)}</div>
        </div>
        <div className="card kpi">
          <div className="l">CPU usada pelo agente</div>
          <div className="v">{ms(perf.cpu_ms)}</div>
          <div className="small muted">{((100 * perf.cpu_ms) / Math.max(perf.wall_ms, 1)).toFixed(0)}% de 1 núcleo, em prioridade baixa</div>
        </div>
        <div className="card kpi">
          <div className="l">Arquivos analisados</div>
          <div className="v">{analyzed}</div>
          <div className="small muted">
            {perf.inspect.cache_hits} reaproveitados do cache ({hitRate(perf.inspect)}%)
          </div>
        </div>
        <div className="card kpi">
          <div className="l">Memória do agente</div>
          <div className="v">{perf.mem_mb.toFixed(0)} MB</div>
        </div>
      </div>
      <div className="small muted" style={{ marginBottom: 8 }}>
        Varredura de {when ? fmtTime(when) : "—"}. Fases:{" "}
        {perf.phases.map((p, i) => (
          <span key={p.phase}>
            {i > 0 && " · "}
            {PHASE_LABEL[p.phase] ?? p.phase} {p.count} itens em {ms(p.ms)}
          </span>
        ))}
      </div>
      <OpsTable p={perf.inspect} />
      <Slowest p={perf.inspect} />
    </>
  );
}

function LiveSection({ agentId }: { agentId: string }) {
  const evs = usePoll(() => api.get<LiveEvent[]>(`/api/events?agent=${agentId}&kind=agent_perf&limit=24`), 60000, [agentId]);
  const list = (evs.data ?? []).map((e) => ({ ts: e.ts, p: e.data?.perf as AgentPerf | undefined })).filter((x) => x.p);
  if (!list.length)
    return (
      <div className="card small muted">
        Ainda sem medição. O agente informa o próprio consumo a cada 5 minutos (versão com medição de custo).
      </div>
    );
  const last = list[0].p!;
  return (
    <>
      <div className="grid kpis">
        <div className="card kpi">
          <div className="l">CPU média (últimos {Math.round(last.window_s / 60)} min)</div>
          <div className="v">{last.cpu_percent.toFixed(2)}%</div>
          <div className="small muted">de 1 núcleo, incluindo varreduras</div>
        </div>
        <div className="card kpi">
          <div className="l">Memória</div>
          <div className="v">{last.mem_mb.toFixed(0)} MB</div>
        </div>
        <div className="card kpi">
          <div className="l">Execuções analisadas</div>
          <div className="v">{last.proc_events}</div>
          <div className="small muted">{last.proc_events ? `${last.enrich_avg_ms.toFixed(1)} ms cada` : "nenhuma no período"}</div>
        </div>
        <div className="card kpi">
          <div className="l">Conexões analisadas</div>
          <div className="v">{last.net_events}</div>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Período até</th>
              <th className="num">CPU</th>
              <th className="num">Memória</th>
              <th className="num">Execuções</th>
              <th className="num">Conexões</th>
              <th className="num">Arquivos (cache)</th>
            </tr>
          </thead>
          <tbody>
            {list.map(({ ts, p }) => (
              <tr key={ts}>
                <td>{fmtTime(ts / 1000)}</td>
                <td className="num">{p!.cpu_percent.toFixed(2)}%</td>
                <td className="num">{p!.mem_mb.toFixed(0)} MB</td>
                <td className="num">{p!.proc_events}</td>
                <td className="num">{p!.net_events}</td>
                <td className="num">
                  {p!.inspect.lookups - p!.inspect.cache_hits} ({hitRate(p!.inspect)}%)
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** Custo de processamento do agente: varreduras e monitor em tempo real. */
export function PerfTab({ agentId, perf, when }: { agentId: string; perf?: ScanPerf; when?: string }) {
  return (
    <>
      <h3>Última varredura</h3>
      <ScanSection perf={perf} when={when} />
      <h3 style={{ marginTop: 22 }}>Consumo contínuo do agente</h3>
      <LiveSection agentId={agentId} />
    </>
  );
}
