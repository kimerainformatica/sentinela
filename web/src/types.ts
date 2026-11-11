export type Severity = "critica" | "alta" | "media" | "baixa";
export type HostStatus = "comprometido" | "suspeito" | "atencao" | "ok" | "sem_dados";

export interface Agent {
  id: string;
  hostname: string;
  os: string;
  agent_version: string;
  enrolled_at: number;
  last_seen: number;
  last_report_at: number;
  remote_ip: string;
  compromised_at: number;
  online: boolean;
  open_findings: number;
  max_severity: Severity | "";
  status: HostStatus;
  pending_commands: number;
}

export interface Scan {
  received_at: number;
  trigger: string;
  autoruns: number;
  processes: number;
  connections: number;
  duration_ms: number;
  open_findings: number;
  max_severity: string;
}

export interface Finding {
  id: number;
  agent_id: string;
  hostname: string;
  rule_id: string;
  severity: Severity;
  title: string;
  detail: string;
  technique: string;
  object_type: "autorun" | "process" | "connection";
  object_ref: string;
  path: string;
  sha256: string;
  status: "aberto" | "resolvido" | "falso_positivo";
  first_seen: number;
  last_seen: number;
  resolved_at: number;
}

export interface FileInfo {
  path: string;
  exists: boolean;
  size?: number;
  sha256?: string;
  created?: string;
  modified?: string;
  signature?: "valid" | "unsigned" | "invalid" | "error";
  signer?: string;
  catalog_signed?: boolean;
  company?: string;
  product?: string;
  description?: string;
  original_filename?: string;
  attributes?: string[];
  origin?: { zone: number; zone_name: string; host_url?: string; referrer_url?: string };
  pe?: { is_pe: boolean; machine?: string; dll?: boolean; compiled?: string; sections?: string[]; max_entropy: number; packer?: string; packed?: boolean; overlay?: number };
  error?: string;
}

export interface Autorun {
  id: string;
  category: string;
  location: string;
  name: string;
  command: string;
  image_path: string;
  enabled: boolean;
  user?: string;
  file?: FileInfo;
  payload?: FileInfo;
}

export interface Process {
  pid: number;
  ppid: number;
  name: string;
  image_path?: string;
  command_line?: string;
  user?: string;
  started?: string;
  file?: FileInfo;
}

export interface Connection {
  proto: string;
  local_addr: string;
  local_port: number;
  remote_addr?: string;
  remote_port?: number;
  state?: string;
  pid: number;
  process_name?: string;
}

export interface Report {
  collected_at: string;
  duration_ms: number;
  trigger: string;
  host: { hostname: string; os: string; os_build: string; domain?: string; ips?: string[]; agent_version: string; is_elevated: boolean };
  autoruns: Autorun[] | null;
  processes: Process[] | null;
  connections: Connection[] | null;
  errors?: string[];
  perf?: ScanPerf;
}

export interface OpCost {
  count: number;
  ms: number;
  bytes?: number;
}

export interface InspectPerf {
  lookups: number;
  cache_hits: number;
  ops: Record<string, OpCost>;
  slowest?: { path: string; ms: number }[];
}

export interface ScanPerf {
  wall_ms: number;
  cpu_ms: number;
  mem_mb: number;
  phases: { phase: string; count: number; ms: number }[];
  inspect: InspectPerf;
}

export interface AgentPerf {
  window_s: number;
  cpu_percent: number;
  mem_mb: number;
  goroutines: number;
  proc_events: number;
  net_events: number;
  enrich_avg_ms: number;
  inspect: InspectPerf;
}

export interface FloodBlock {
  ip: string;
  created: number;
  expires: number;
  reason: string;
}

export interface HashRep {
  status: "pending" | "known" | "unknown" | "error";
  malicious: number;
  suspicious: number;
  total: number;
  label: string;
}

export interface IPRep {
  status: string;
  score: number;
  country: string;
  isp: string;
  reports: number;
}

export interface Snapshot {
  report: Report;
  hashes: Record<string, HashRep>;
  ips: Record<string, IPRep>;
  intel: { vt: boolean; abuseipdb: boolean };
}

export interface Command {
  id: string;
  action: string;
  params: Record<string, string>;
  status: "pendente" | "enviado" | "sucesso" | "falha" | "expirado";
  created_at: number;
  created_by: string;
  delivered_at: number;
  finished_at: number;
  result: string;
  undo_id: string;
}

export interface Overview {
  agents: number;
  online: number;
  status: Partial<Record<HostStatus, number>>;
  findings_by_severity: Partial<Record<Severity, number>>;
  intel: { vt_enabled: boolean; abuseipdb_enabled: boolean; hashes_pending: number; hashes_checked: number };
}

export interface Settings {
  enroll_token: string;
  fingerprint: string;
  fingerprint_hex: string;
  server_urls: string[] | null;
  vt_enabled: boolean;
  abuseipdb_enabled: boolean;
}

export interface AuditEntry {
  ts: number;
  actor: string;
  action: string;
  agent_id: string;
  hostname: string;
  detail: string;
}

/** Execução de programa capturada em tempo real. */
export interface Execution {
  id: number;
  ts: number; // ms
  pid: number;
  ppid: number;
  name: string;
  image: string;
  command_line: string;
  user: string;
  parent_name: string;
  parent_image: string;
  sha256: string;
  signature: "" | "valid" | "unsigned" | "invalid" | "error";
  signer: string;
  company: string;
  source: "etw" | "poll";
  exited: boolean;
  restricted: boolean;
  vt: HashRep | { status: ""; malicious: number; total: number; label: string; suspicious: number };
}

/** Conexão TCP capturada em tempo real. */
export interface NetConn {
  id: number;
  ts: number; // ms
  pid: number;
  process: string;
  image: string;
  direction: "saida" | "entrada";
  proto: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  sha256: string;
  signature: "" | "valid" | "unsigned" | "invalid" | "error";
  signer: string;
  source: "etw" | "poll";
  repeats: number;
  public: boolean;
  ip: IPRep;
}
