import { useState } from "react";
import { api } from "../api";
import { ConfirmModal, StatusBadge, useToast, type ConfirmSpec } from "../components";
import type { Agent, Command, Finding, Scan, Snapshot } from "../types";
import { TRIGGER_LABEL, ago, fmtTime, isMicrosoft, usePoll } from "../util";
import { FindingCard } from "./Findings";
import { useLiveEvents, useLiveRefresh, useLiveStatus } from "../live";
import { LiveFeed, StatusPill } from "../LiveFeed";
import { ActionsTab, AutorunsTab, DisableAutorunButton, ExecutionsTab, KillButton, NetLiveTab, NetworkTab, ProcessesTab, QuarantineButton, type SendFn } from "./AgentTabs";

type Tab = "achados" | "execucoes" | "rede-tr" | "inicializacao" | "processos" | "rede" | "acoes";

type StepState = "done" | "warn" | "bad" | "todo";
interface Step {
  title: string;
  detail: string;
  state: StepState;
}

/**
 * Checklist com as etapas do procedimento documentado no relatório técnico
 * (Autoruns + VirusTotal + netstat + remoção + verificação posterior),
 * preenchido automaticamente a partir dos dados do agente.
 */
function procedureSteps(snap: Snapshot | null, findings: Finding[], commands: Command[], scans: Scan[]): Step[] {
  if (!snap) return [];
  const r = snap.report;
  const autoruns = r.autoruns ?? [];
  const open = findings.filter((f) => f.status === "aberto");
  const serious = open.filter((f) => f.severity === "critica" || f.severity === "alta");
  const hashes = Object.values(snap.hashes);
  const checked = hashes.filter((h) => h.status === "known" || h.status === "unknown").length;
  const pending = hashes.filter((h) => h.status === "pending").length;
  const remediations = commands.filter((c) => c.status === "sucesso" && c.action !== "rescan" && !c.action.startsWith("restore"));
  const lastRemediation = Math.max(0, ...remediations.map((c) => c.finished_at));
  const postScan = scans.find((s) => s.trigger === "pos-remediacao" && s.received_at >= lastRemediation);
  const established = (r.connections ?? []).filter((c) => c.state === "ESTABLISHED").length;
  const nonMs = autoruns.filter((a) => !isMicrosoft(a.file)).length;

  return [
    {
      title: "Coleta com privilégios de administrador",
      detail: r.host.is_elevated ? `Varredura ${TRIGGER_LABEL[r.trigger]?.toLowerCase() ?? r.trigger} em ${fmtTime(r.collected_at)}` : "Agente sem privilégios: coleta incompleta",
      state: r.host.is_elevated ? "done" : "bad",
    },
    {
      title: "Análise da inicialização automática",
      detail: `${autoruns.length} entradas analisadas (${nonMs} fora da Microsoft)`,
      state: "done",
    },
    {
      title: "Reputação no VirusTotal",
      detail: !snap.intel.vt ? "VirusTotal não configurado: use o link manual em cada arquivo" : `${checked} arquivos consultados${pending ? `, ${pending} na fila` : ""}`,
      state: !snap.intel.vt ? "warn" : pending ? "warn" : "done",
    },
    {
      title: "Identificação de entradas suspeitas",
      detail: open.length ? `${open.length} achados abertos (${serious.length} crítico/alto)` : "Nenhum achado aberto",
      state: serious.length ? "bad" : open.length ? "warn" : "done",
    },
    {
      title: "Remoção das entradas maliciosas",
      detail: remediations.length ? `${remediations.length} ações concluídas` : serious.length ? "Pendente: há achados graves sem ação" : "Nenhuma ação necessária",
      state: remediations.length && !serious.length ? "done" : serious.length ? "bad" : remediations.length ? "warn" : "done",
    },
    {
      title: "Verificação das conexões de rede",
      detail: `${established} conexões estabelecidas${snap.intel.abuseipdb ? ", IPs consultados no AbuseIPDB" : ""}`,
      state: open.some((f) => f.object_type === "connection") ? "bad" : "done",
    },
    {
      title: "Verificação posterior",
      detail: !remediations.length ? "Aplica-se após uma remediação" : postScan ? `Nova varredura em ${fmtTime(postScan.received_at)}: ${postScan.open_findings} achados abertos` : "Aguardando nova varredura do agente",
      state: !remediations.length ? "todo" : postScan ? (postScan.open_findings ? "warn" : "done") : "warn",
    },
  ];
}

export default function AgentDetail({ id }: { id: string }) {
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("achados");
  const [showResolved, setShowResolved] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmSpec | null>(null);

  const info = usePoll(() => api.get<{ agent: Agent; scans: Scan[] }>(`/api/agents/${id}`), 10000, [id]);
  const snap = usePoll(() => api.get<Snapshot>(`/api/agents/${id}/snapshot`), 15000, [id]);
  const findings = usePoll(() => api.get<Finding[]>(`/api/findings?agent=${id}&status=todos`), 10000, [id]);
  const commands = usePoll(() => api.get<Command[]>(`/api/agents/${id}/commands`), 5000, [id]);

  const reloadAll = () => {
    info.reload();
    snap.reload();
    findings.reload();
    commands.reload();
  };
  // Atualiza a tela assim que algo acontece com esta máquina.
  useLiveRefresh(reloadAll, (e) => e.agent_id === id && e.category !== "painel" && e.kind !== "scan_phase");
  const live = useLiveEvents({ agent: id, limit: 40 });
  const liveStatus = useLiveStatus();

  const send: SendFn = (action, params, title, body, danger) =>
    setConfirm({
      title,
      body: <p>{body}</p>,
      confirm: "Enviar ao agente",
      danger,
      onConfirm: async () => {
        try {
          await api.post(`/api/agents/${id}/commands`, { action, params });
          toast("Comando enviado. O agente executa em até 30 segundos e faz uma nova varredura em seguida.");
          commands.reload();
        } catch (e) {
          toast((e as Error).message, true);
        }
      },
    });

  if (info.error && !info.data) return <div className="alert crit">{info.error}</div>;
  const a = info.data?.agent;
  if (!a) return null;

  const allF = findings.data ?? [];
  const open = allF.filter((f) => f.status === "aberto");
  const shownF = showResolved ? allF : open;
  const s = snap.data;
  const steps = procedureSteps(s, allF, commands.data ?? [], info.data?.scans ?? []);
  const autoruns = s?.report.autoruns ?? [];
  const procs = s?.report.processes ?? [];

  /** Botões de remediação relevantes para cada achado. */
  const findingActions = (f: Finding) => {
    if (!s || f.status !== "aberto") return null;
    if (f.object_type === "autorun") {
      const ar = autoruns.find((x) => x.id === f.object_ref);
      if (!ar) return null;
      return (
        <>
          {ar.enabled && <DisableAutorunButton a={ar} send={send} />}
          <QuarantineButton f={ar.payload ?? ar.file} send={send} />
        </>
      );
    }
    const path = f.path.toLowerCase();
    const running = procs.filter((p) => p.image_path?.toLowerCase() === path);
    return (
      <>
        {running.map((p) => (
          <KillButton key={p.pid} p={p} send={send} />
        ))}
        <QuarantineButton f={running[0]?.file} send={send} />
      </>
    );
  };

  const tabs: [Tab, string, number | null][] = [
    ["achados", "Achados", open.length],
    ["execucoes", "Execuções em tempo real", null],
    ["rede-tr", "Rede em tempo real", null],
    ["inicializacao", "Inicialização automática", autoruns.length],
    ["processos", "Processos", procs.length],
    ["rede", "Conexões (última varredura)", (s?.report.connections ?? []).filter((c) => c.state === "ESTABLISHED").length],
    ["acoes", "Ações e verificação", (commands.data ?? []).length],
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small">
            <a href="#/">← Endpoints</a>
          </div>
          <h1>
            <span className={`dot ${a.online ? "on" : ""}`} />
            {a.hostname} <StatusBadge status={a.status} />
          </h1>
          <div className="muted small">
            {a.os} · IP {a.remote_ip} · agente {a.agent_version || "—"} · visto {ago(a.last_seen)} · última varredura {ago(a.last_report_at)}
          </div>
        </div>
        <div className="row">
          <button
            className="btn primary"
            onClick={() => send("rescan", {}, "Executar nova varredura?", "O agente fará uma varredura completa e enviará o resultado em seguida.")}
          >
            Nova varredura
          </button>
          <button
            className="btn danger"
            onClick={() =>
              setConfirm({
                title: `Remover ${a.hostname} do painel?`,
                body: <p>O histórico deste endpoint será apagado. Se o agente continuar instalado na máquina, ele deixará de ser aceito pelo servidor.</p>,
                confirm: "Remover",
                danger: true,
                onConfirm: async () => {
                  await api.del(`/api/agents/${id}`);
                  window.location.hash = "#/";
                },
              })
            }
          >
            Remover
          </button>
        </div>
      </div>

      {a.compromised_at > 0 && (
        <div className="alert crit">
          <strong>Comprometimento detectado em {fmtTime(a.compromised_at)}: reinstalação limpa recomendada</strong>
          Desativar entradas e colocar arquivos em quarentena não garante, sozinho, a eliminação completa de um Cavalo de Troia. Quando não é possível
          assegurar a remoção total da ameaça, o procedimento mais indicado é formatar o equipamento e reinstalar o sistema e os programas a partir de
          fontes confiáveis. Troque também as senhas usadas nesta máquina.
          <div className="row" style={{ marginTop: 10 }}>
            <button
              className="btn sm"
              onClick={() =>
                setConfirm({
                  title: "Confirmar reinstalação limpa?",
                  body: <p>Use após formatar e reinstalar o equipamento (ou após concluir que a remoção foi completa). O alerta deixará de ser exibido.</p>,
                  confirm: "Confirmar",
                  onConfirm: async () => {
                    await api.post(`/api/agents/${id}/clear-compromise`);
                    reloadAll();
                  },
                })
              }
            >
              Confirmar reinstalação limpa
            </button>
          </div>
        </div>
      )}
      {s?.report.errors?.length ? (
        <div className="alert warn">
          <strong>Avisos da última coleta</strong>
          {s.report.errors.slice(0, 5).map((e, i) => (
            <div key={i} className="small break">
              {e}
            </div>
          ))}
        </div>
      ) : null}
      {snap.error && !s && <div className="alert info">{snap.error}</div>}

      {steps.length > 0 && (
        <div className="card">
          <h3>Procedimento de verificação</h3>
          <div className="steps">
            {steps.map((st, i) => (
              <div key={i} className={`step ${st.state}`}>
                <div className="t">
                  <span className="i">{st.state === "done" ? "✓" : st.state === "bad" ? "!" : st.state === "warn" ? "…" : i + 1}</span>
                  {st.title}
                </div>
                <div className="d">{st.detail}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0, marginTop: 14 }}>
        <div className="row" style={{ justifyContent: "space-between", padding: "12px 16px 4px" }}>
          <h3 style={{ margin: 0 }}>
            Atividade ao vivo <StatusPill status={liveStatus} />
          </h3>
          <a href="#/ao-vivo" className="small">
            ver todos os eventos →
          </a>
        </div>
        <div className="feed-compact">
          <LiveFeed events={live.events.slice(0, 12)} showHost={false} empty="Nenhuma atividade registrada para esta máquina ainda." />
        </div>
      </div>

      <div className="tabs" role="tablist">
        {tabs.map(([k, label, n]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {label}
            {n !== null && <span className="n">{n}</span>}
          </button>
        ))}
      </div>

      {tab === "achados" && (
        <>
          <label className="check" style={{ marginBottom: 12 }}>
            <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
            Mostrar também resolvidos e falsos positivos
          </label>
          {shownF.length === 0 && <div className="alert info">Nenhum achado {showResolved ? "" : "aberto "}neste endpoint.</div>}
          <div className="list">
            {shownF.map((f) => (
              <FindingCard key={f.id} f={f} onChange={findings.reload} actions={findingActions(f)} />
            ))}
          </div>
        </>
      )}
      {tab === "execucoes" && <ExecutionsTab agentId={id} findings={allF} send={send} />}
      {tab === "rede-tr" && <NetLiveTab agentId={id} findings={allF} />}
      {s && tab === "inicializacao" && <AutorunsTab snap={s} findings={allF} send={send} />}
      {s && tab === "processos" && <ProcessesTab snap={s} findings={allF} send={send} />}
      {s && tab === "rede" && <NetworkTab snap={s} findings={allF} send={send} />}
      {tab === "acoes" && <ActionsTab commands={commands.data ?? []} scans={info.data?.scans ?? []} send={send} autoruns={autoruns} />}

      <ConfirmModal spec={confirm} onClose={() => setConfirm(null)} />
    </>
  );
}
