import { useState } from "react";
import { api } from "../api";
import { ConfirmModal, useToast, type ConfirmSpec } from "../components";
import type { Settings } from "../types";
import { usePoll } from "../util";

export default function SettingsPage() {
  const { data, reload } = usePoll(() => api.get<Settings>("/api/settings"), 60000);
  const toast = useToast();
  const [confirm, setConfirm] = useState<ConfirmSpec | null>(null);
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");

  const url = data?.server_urls?.[0] ?? "https://IP-DO-SERVIDOR:8443";
  const cmd = data
    ? `.\\sentinela-agent.exe install -server ${url} -token ${data.enroll_token} -fingerprint ${data.fingerprint_hex}`
    : "";

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Instalação e ajustes</h1>
          <div className="muted">Como colocar o agente nas máquinas e configurações do servidor</div>
        </div>
      </div>

      <div className="grid" style={{ gap: 16 }}>
        <div className="card">
          <h2>Instalar o agente em uma máquina</h2>
          <ol style={{ lineHeight: 1.7, paddingLeft: 18 }}>
            <li>
              Copie <code>sentinela-agent.exe</code> para a máquina (pendrive ou pasta compartilhada).
            </li>
            <li>Abra o PowerShell <strong>como Administrador</strong> na pasta do arquivo.</li>
            <li>Execute o comando abaixo. O agente se cadastra, vira um serviço do Windows e envia a primeira varredura.</li>
          </ol>
          <pre className="box mono">{cmd}</pre>
          <div className="row">
            <button
              className="btn"
              onClick={() => {
                navigator.clipboard.writeText(cmd).then(
                  () => toast("Comando copiado"),
                  () => toast("Não foi possível copiar", true),
                );
              }}
            >
              Copiar comando
            </button>
            {data?.server_urls && data.server_urls.length > 1 && (
              <span className="small muted">Outros endereços deste servidor: {data.server_urls.slice(1).join(", ")}</span>
            )}
          </div>
          <p className="small muted">
            Impressão digital do certificado: <span className="mono">{data?.fingerprint}</span>
            <br />O agente só conversa com um servidor que apresente exatamente este certificado.
          </p>
          <button
            className="btn danger sm"
            onClick={() =>
              setConfirm({
                title: "Gerar novo token de cadastro?",
                body: "O token atual deixará de funcionar para novas instalações. Agentes já instalados continuam funcionando normalmente.",
                confirm: "Gerar novo token",
                danger: true,
                onConfirm: async () => {
                  await api.post("/api/settings/rotate-token");
                  reload();
                  toast("Novo token gerado");
                },
              })
            }
          >
            Gerar novo token
          </button>
        </div>

        <div className="card">
          <h2>Inteligência de ameaças</h2>
          <p>
            VirusTotal (reputação de arquivos):{" "}
            <span className={`badge ${data?.vt_enabled ? "st-ok" : "st-expirado"}`}>{data?.vt_enabled ? "ativo" : "desativado"}</span>
            <br />
            AbuseIPDB (reputação de IPs):{" "}
            <span className={`badge ${data?.abuseipdb_enabled ? "st-ok" : "st-expirado"}`}>{data?.abuseipdb_enabled ? "ativo" : "desativado"}</span>
          </p>
          <p className="small muted">
            Para ativar, defina as variáveis de ambiente <code>SENTINELA_VT_KEY</code> e <code>SENTINELA_ABUSEIPDB_KEY</code> antes de iniciar o
            servidor (as contas gratuitas bastam). Apenas o <strong>hash</strong> dos arquivos é consultado; nenhum arquivo da instituição é enviado.
          </p>
        </div>

        <div className="card">
          <h2>Alterar senha do administrador</h2>
          <div className="row">
            <input type="password" placeholder="Senha atual" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
            <input type="password" placeholder="Nova senha (mín. 12 caracteres)" value={nw} onChange={(e) => setNw(e.target.value)} autoComplete="new-password" />
            <button
              className="btn primary"
              disabled={!cur || nw.length < 12}
              onClick={async () => {
                try {
                  await api.post("/api/settings/password", { current: cur, new: nw });
                  setCur("");
                  setNw("");
                  toast("Senha alterada");
                } catch (e) {
                  toast((e as Error).message, true);
                }
              }}
            >
              Alterar
            </button>
          </div>
        </div>
      </div>
      <ConfirmModal spec={confirm} onClose={() => setConfirm(null)} />
    </>
  );
}
