# Sentinela — MVP de detecção e resposta em endpoints Windows

O Sentinela automatiza o procedimento de remoção de Cavalo de Troia documentado no relatório técnico
*"Pesquisa e aplicação de método alternativo para remoção de malware"*: análise da inicialização
automática (Autoruns), reputação no VirusTotal, conexões de rede (`netstat -ano`), remoção das
entradas maliciosas e verificação posterior. A diferença é que tudo roda de forma contínua, em
todas as máquinas, com registro de cada ação.

```
┌──────────────── Endpoint Windows ────────────────┐
│ sentinela-agent.exe (serviço, roda como SYSTEM)  │
│  • Inicialização automática (estilo Autoruns)    │
│  • Processos + linha de comando + usuário        │
│  • Conexões TCP/UDP por processo (netstat -ano)  │
│  • Hash SHA-256, assinatura digital, fabricante  │
│  • Remediação reversível (backup / quarentena)   │
└───────────────┬──────────────────────────────────┘
                │ HTTPS + pinning do certificado
                │ relatório a cada 30 min · comandos a cada 30 s
┌───────────────▼──────────────────────────────────┐
│ sentinela-server.exe                             │
│  • API dos agentes (cadastro por token)          │
│  • Motor de regras (16 regras, MITRE ATT&CK)     │
│  • VirusTotal (hash) + AbuseIPDB (IP), com cache │
│  • Comandos assinados com Ed25519                │
│  • SQLite · painel React embutido · auditoria    │
└──────────────────────────────────────────────────┘
```

## Do procedimento manual ao sistema

| Etapa do relatório técnico | No Sentinela |
|---|---|
| Executar o Autoruns como administrador | Agente roda como serviço (SYSTEM) e enumera: chaves Run/RunOnce (máquina e cada usuário), pasta Inicializar (resolve atalhos `.lnk`), serviços, drivers, tarefas agendadas, Winlogon, IFEO, AppInit_DLLs e Active Setup |
| Verificação integrada com o VirusTotal | Servidor consulta o **hash** (o arquivo nunca é enviado) com fila priorizada: primeiro autoruns sem assinatura, depois processos. Itens assinados pela Microsoft são ignorados, como o "Hide Microsoft Entries" do Autoruns |
| Identificar entradas com detecções | Regra R01 (≥5 detecções = crítica) e mais 15 heurísticas (tabela abaixo) |
| Verificar local, nome, fabricante, data de criação, propriedades | Cada arquivo traz SHA-256, datas, assinatura Authenticode (inclusive por catálogo do Windows), assinante, fabricante e descrição |
| Remover as entradas maliciosas | Botões no painel: **Desativar** (com backup), **Quarentena** (arquivo codificado, restaurável), **Finalizar processo**. Tudo pode ser desfeito |
| `netstat -ano` | Aba "Conexões de rede", com o processo dono e a reputação do IP remoto |
| Verificação posterior | Após cada remediação o agente faz uma nova varredura sozinho. Achados que sumiram ficam "resolvidos" |
| Recomendação de formatar | Um achado crítico marca a máquina como **comprometida** e mostra a recomendação de reinstalação limpa até alguém confirmar que ela foi feita |

## Regras de detecção

| ID | Severidade | O que detecta | ATT&CK |
|---|---|---|---|
| R01 | crítica / alta / média | Arquivo com detecções no VirusTotal (≥5 / 2–4 / 1) | T1204 |
| R02 | alta | Inicialização de arquivo **sem assinatura** em pasta gravável pelo usuário (AppData, Temp, Public, ProgramData…) | T1547.001, T1543.003, T1053.005 |
| R03 | alta | Linha de comando suspeita na inicialização (PowerShell `-enc`/oculto/download, mshta, regsvr32 remoto, certutil…) | T1059 |
| R04 | alta | Assinatura digital inválida (arquivo adulterado) | T1036.001 |
| R05 | crítica | Nome de binário do Windows fora da pasta do sistema (ex.: `svchost.exe` em AppData) | T1036.005 |
| R06 | crítica | Winlogon `Shell`/`Userinit` alterado | T1547.004 |
| R07 | alta | Sequestro via Image File Execution Options (Debugger) | T1546.012 |
| R08 | alta | DLL em AppInit_DLLs | T1546.010 |
| R09 | baixa | Entrada de inicialização apontando para arquivo inexistente | T1547 |
| R10 | alta | Programa sem assinatura em pasta do usuário com conexão externa | T1071 |
| R11 | crítica / média | Conexão com IP de má reputação (AbuseIPDB ≥75% / ≥25%) | T1071 |
| R12 | média | Arquivo de inicialização sem assinatura criado nos últimos 7 dias | T1547 |
| R13 | alta | Driver sem assinatura válida | T1014 |
| R14 | alta | Word/Excel/Outlook/PDF abrindo PowerShell, cmd, wscript… (macro maliciosa) | T1204.002 |
| R15 | alta | Processo com linha de comando suspeita | T1059 |
| R16 | média | Programa sem assinatura em pasta do usuário aguardando conexões (possível backdoor) | T1571 |
| R17 | média | *(tempo real)* Programa sem assinatura **executado** de pasta do usuário (Downloads, Temp, AppData…) | T1204.002 |
| R18 | média | *(tempo real)* Conexão para porta típica de ataque/C2 (4444, IRC, Tor…) | T1571 |
| R19 | alta / média | *(tempo real)* Script ou utilitário do Windows conectando à internet (mshta, rundll32, wscript, certutil… / PowerShell) | T1105 |

As regras de processo (R01, R04, R05, R14, R15, R17) e de rede (R10, R11, R16, R18, R19) também rodam **no instante do evento** (veja abaixo),
então pegam até um PowerShell que dura meio segundo. Esses achados ficam abertos até o analista marcá-los como
resolvidos, já que o processo pode não existir mais na varredura seguinte.

## Execuções e conexões em tempo real

Além das varreduras periódicas, o agente captura **cada programa no momento em que é aberto** (linha de
comando, usuário, processo pai, assinatura e hash) e **cada conexão TCP no momento em que é aberta ou aceita**
(processo dono, destino, porta). Tudo aparece na tela **Ao vivo** e nas abas **Execuções em tempo real** e
**Rede em tempo real** de cada máquina. Conexões repetidas do mesmo programa para o mesmo destino são agrupadas
(um evento a cada 10 minutos, com o número de repetições).

| Agente rodando como | Fonte | Cobertura |
|---|---|---|
| Serviço (SYSTEM) / administrador | **ETW**: provedor de processos do kernel + `Microsoft-Windows-Kernel-Process` + `Microsoft-Windows-Kernel-Network` (só eventos de conexão, filtrados no kernel) | Todos os processos com linha de comando, inclusive os de milissegundos; todas as conexões TCP |
| Usuário comum (modo `dev`) | Verificação a cada 1 s (processos) e 2 s (conexões) | O que fica aberto por mais que esse intervalo |

Diagnóstico local: `sentinela-agent.exe procmon -for 30s` mostra as execuções no terminal e informa qual fonte está ativa.

## Ver o sistema funcionando (desenvolvimento)

```powershell
.\bin\sentinela-server.exe -addr 127.0.0.1:8443 -data .\data
# em outro terminal (o comando completo aparece em "Instalação e ajustes" no painel):
.\bin\sentinela-agent.exe dev -token <TOKEN> -fingerprint <SHA256>
```

O modo `dev` roda o agente em primeiro plano, **sem instalar serviço e sem exigir administrador**, com varredura
a cada 2 minutos. Abra a tela **Ao vivo** do painel para acompanhar cada etapa.

## Compilar

Requisitos: Go 1.24+ e Node 18+.

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

## Rodar o servidor

```powershell
# Opcional: chaves gratuitas de https://www.virustotal.com e https://www.abuseipdb.com
$env:SENTINELA_VT_KEY = "..."
$env:SENTINELA_ABUSEIPDB_KEY = "..."

.\bin\sentinela-server.exe -addr :8443 -data .\data
```

Na primeira execução o console mostra a **senha do admin** (uma única vez), o **token de cadastro**, a
**impressão digital do certificado** e o comando pronto para instalar o agente. O painel fica em
`https://<ip-do-servidor>:8443`. O navegador vai alertar sobre o certificado autoassinado, o que é esperado.

Libere a porta 8443 no firewall do servidor para a rede interna. Outros comandos:
`-reset-admin` (nova senha) e `-rotate-token` (novo token de cadastro).

## Instalar o agente nas máquinas

Em cada máquina, PowerShell **como Administrador** (o comando completo aparece em *Instalação e ajustes* no painel):

```powershell
.\sentinela-agent.exe install -server https://192.168.0.10:8443 -token <TOKEN> -fingerprint <SHA256>
```

O agente se copia para `C:\Program Files\Sentinela`, cria o serviço `Sentinela` (início automático,
reinício em caso de falha) e guarda configuração, backups e quarentena em `C:\ProgramData\Sentinela`,
pasta acessível só por SYSTEM e Administradores. Para remover: `sentinela-agent.exe uninstall`
(a pasta de dados é mantida de propósito, para não perder a quarentena).

Para usar **sem servidor**, como um "Autoruns de linha de comando": `sentinela-agent.exe scan -out relatorio.json`.

## Segurança do próprio sistema

O agente roda como SYSTEM, então o canal de comandos é o alvo mais valioso. Por isso:

- **TLS com pinning**: o agente só aceita o certificado cuja impressão digital SHA-256 foi informada na instalação (impede ataque man-in-the-middle mesmo com certificado autoassinado).
- **Credencial por agente**: segredo aleatório de 256 bits; o servidor guarda só o hash.
- **Comandos assinados com Ed25519**: com ID do agente de destino e validade de 1 hora. O agente rejeita assinatura inválida, comando de outro agente, comando expirado e comando repetido.
- **Allowlist de ações** no servidor e no agente: só existem `rescan`, `kill_process`, `disable_autorun`, `restore_autorun`, `quarantine_file` e `restore_file`. Não há execução de comandos arbitrários.
- **Travas no agente**: confere o caminho do processo antes de finalizar (evita reuso de PID), recusa finalizar processos críticos do Windows, confere o hash do arquivo antes da quarentena e recusa colocar em quarentena arquivos assinados pela Microsoft.
- **Painel**: senha com PBKDF2-SHA256 (600 mil iterações), cookie `HttpOnly`/`Secure`/`SameSite=Strict`, cabeçalho anti-CSRF, bloqueio após 5 tentativas, CSP, e auditoria de cada login e cada comando.

## Limitações conhecidas (próximos passos)

1. **Tempo real para processos e conexões TCP.** Persistência (registro, tarefas) e arquivos ainda são vistos apenas nas varreduras periódicas; UDP/DNS não são monitorados. Próximo passo: ETW de registro e de DNS. Sem administrador, processos e conexões muito curtos podem escapar.
2. **Persistência ainda não coberta**: assinaturas WMI, extensões do Explorer, COM hijacking, hives de usuários deslogados.
3. **Um único usuário (admin)**. Próximo passo: múltiplos usuários com papéis (leitura / analista / admin).
4. **SQLite** atende algumas dezenas de máquinas com snapshots. Com telemetria em tempo real (item 1), migrar os eventos para ClickHouse.
5. **Executável do agente não assinado**: antivírus e SmartScreen podem desconfiar. Para produção, assinar com certificado de *code signing*.
6. Sem autoproteção contra adulteração: um malware com privilégio de administrador pode parar o serviço. A ausência de contato aparece no painel como "offline".

## Estrutura

```
cmd/agent, cmd/server        pontos de entrada
internal/model               contrato agente ↔ servidor
internal/agent/collect       coletores (autoruns, processos, rede, arquivos)
internal/agent/remediate     ações de resposta reversíveis
internal/agent               serviço Windows, cliente HTTPS, spool offline
internal/server              API, regras, threat intel, banco, autenticação
web/                         painel React (embutido no servidor)
```
