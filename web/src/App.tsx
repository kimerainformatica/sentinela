import { useEffect, useState, type FormEvent } from "react";
import { api, setUnauthorizedHandler } from "./api";
import Overview from "./pages/Overview";
import Findings from "./pages/Findings";
import AgentDetail from "./pages/AgentDetail";
import SettingsPage from "./pages/Settings";
import Audit from "./pages/Audit";

function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const on = () => setHash(window.location.hash || "#/");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash.slice(1);
}

const Logo = () => (
  <svg viewBox="0 0 32 32" aria-hidden="true">
    <path d="M16 2 4 7v8c0 7.5 5.1 13.6 12 15 6.9-1.4 12-7.5 12-15V7z" fill="#14b8a6" />
    <path d="m10 16 4 4 8-8" stroke="#04201d" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

function Login({ onLogin }: { onLogin: () => void }) {
  const [user, setUser] = useState("admin");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.post("/api/login", { username: user, password: pw });
      onLogin();
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ padding: 0 }}>
          <Logo /> Sentinela
        </div>
        <p className="muted" style={{ margin: 0 }}>
          Painel de resposta a incidentes
        </p>
        <input type="text" value={user} onChange={(e) => setUser(e.target.value)} placeholder="Usuário" autoComplete="username" />
        <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Senha" autoComplete="current-password" autoFocus />
        {err && <div className="error">{err}</div>}
        <button className="btn primary" disabled={busy || !pw}>
          {busy ? "Entrando…" : "Entrar"}
        </button>
      </form>
    </div>
  );
}

export default function App() {
  const [auth, setAuth] = useState<"loading" | "in" | "out">("loading");
  const route = useHashRoute();

  useEffect(() => {
    setUnauthorizedHandler(() => setAuth("out"));
    api
      .get("/api/me")
      .then(() => setAuth("in"))
      .catch(() => setAuth("out"));
  }, []);

  if (auth === "loading") return null;
  if (auth === "out") return <Login onLogin={() => setAuth("in")} />;

  let page;
  const m = route.match(/^\/endpoint\/([0-9a-f]+)/);
  if (m) page = <AgentDetail id={m[1]} />;
  else if (route.startsWith("/achados")) page = <Findings />;
  else if (route.startsWith("/config")) page = <SettingsPage />;
  else if (route.startsWith("/auditoria")) page = <Audit />;
  else page = <Overview />;

  const link = (href: string, label: string, active: boolean) => (
    <a href={href} className={active ? "active" : ""}>
      {label}
    </a>
  );

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <Logo /> Sentinela
        </div>
        <nav className="nav">
          {link("#/", "Endpoints", route === "/" || !!m)}
          {link("#/achados", "Achados", route.startsWith("/achados"))}
          {link("#/auditoria", "Auditoria", route.startsWith("/auditoria"))}
          {link("#/config", "Instalação e ajustes", route.startsWith("/config"))}
        </nav>
        <div className="spacer" />
        <button
          className="btn sm"
          onClick={async () => {
            await api.post("/api/logout").catch(() => {});
            setAuth("out");
          }}
        >
          Sair
        </button>
      </aside>
      <main className="main">{page}</main>
    </div>
  );
}
