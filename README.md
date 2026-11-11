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
│  • Motor de regras (26 regras, MITRE ATT&CK)     │
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
| Identificar entradas com detecções | Regra R01 (≥5 detecções = crítica) e mais 23 heurísticas (tabela abaixo) |
| Verificar local, nome, fabricante, data de criação, propriedades | Cada arquivo traz SHA-256, datas, atributos, assinatura Authenticode (inclusive por catálogo do Windows), assinante, fabricante, descrição e nome original. Além disso: **de onde foi baixado** (Mark of the Web) e, para arquivos sem assinatura, a **estrutura do executável** (data de compilação, seções, entropia e empacotadores como UPX/Themida/VMProtect) |
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
| R20 | alta | Programa renomeado: PowerShell, cmd, certutil… ou ferramenta de ataque (PsExec, rclone, Mimikatz, ngrok…) salvo com outro nome | T1036.003 |
| R21 | alta | Extensão dupla (`fatura.pdf.exe`) ou caractere invisível de inversão de texto no nome | T1036.007 |
| R22 | média | Executável oculto e sem assinatura em pasta do usuário | T1564.001 |
| R23 | alta / média | Executável empacotado ou cifrado e sem assinatura em pasta do usuário (alta se está na inicialização) | T1027.002 |
| R24 | alta | Inicialização automática de arquivo **baixado da internet** e sem assinatura | T1204.002 |
| R25 | crítica | *(tempo real)* **DDoS de saída**: a máquina está inundando uma vítima de conexões (virou bot) | T1498.001 |
| R26 | alta | *(tempo real)* **DDoS de entrada**: avalanche de conexões chega a uma porta da máquina | T1499 |

As regras de processo (R01, R04, R05, R14, R15, R17) e de rede (R10, R11, R16, R18, R19) também rodam **no instante do evento** (veja abaixo),
então pegam até um PowerShell que dura meio segundo. Esses achados ficam abertos até o analista marcá-los como
resolvidos, já que o processo pode não existir mais na varredura seguinte.

## Detecção e resposta a DDoS

O agente observa **cada conexão TCP no instante em que ela acontece** (o mesmo ETW das execuções) e mantém
contadores por processo e por porta numa janela curta. Quando vira uma avalanche, ele **age sozinho**, sem esperar
um analista — é o "identifica e interrompe":

| Lado | O que é | Resposta automática |
|---|---|---|
| **Saída** | Um processo abre centenas de conexões num piscar de olhos (a máquina virou bot e está atacando) | **Finaliza o processo** atacante (R25, máquina marcada como comprometida) |
| **Entrada** | Uma enxurrada de conexões chega a uma porta da máquina (a máquina é a vítima) | **Bloqueia no Firewall do Windows** os IPs que mais atacam (R26), bloqueio reversível e que expira sozinho |

Limites padrão (janela de 10 s, ajustáveis no código): 300 conexões ao mesmo destino, 150 destinos distintos ou
800 conexões no total (saída); 400 conexões a uma porta, com bloqueio dos IPs que passam de 80 conexões (entrada).
São altos de propósito: navegador, sincronização e torrent espalham-se por muitos destinos com poucas conexões
cada, enquanto um DDoS concentra um volume alto num intervalo curto.

**Travas de segurança** (o agente roda como SYSTEM e age sozinho):

- Nunca finaliza processos críticos do Windows; para programas **assinados** que se espalham (possível P2P), só alerta.
- Nunca bloqueia o IP do servidor nem os da própria máquina (não corta o canal de gerência).
- Bloqueios de firewall são **reversíveis** (botão no painel) e **expiram** (1 h por padrão).
- Um ataque distribuído por milhares de origens leves é **alertado**, mas não gera bloqueio (não há IP concentrado
  para bloquear, e bloquear a porta inteira seria negar o serviço a todos).
- A resposta automática pode ser **desligada pelo painel** (aba *Proteção DDoS*): aí os ataques são só detectados
  e alertados. Cada incidente e cada bloqueio ficam na auditoria.

Monitora TCP; floods de **UDP** (amplificação) e **SYN** puro (sem completar a conexão) ainda não são vistos —
próximo passo, junto com o ETW de UDP.

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

## Custo de processamento

O agente mede o próprio custo e mostra na aba **Desempenho** de cada máquina: tempo e CPU de cada varredura,
quanto cada operação custou (SHA-256, assinatura, catálogo do Windows, análise do executável…), quantos arquivos
vieram do cache, os arquivos mais demorados e, a cada 5 minutos, o consumo contínuo (CPU, memória, execuções e
conexões analisadas). No terminal: `sentinela-agent.exe bench [-n 3] [-live 30s]`.

Medido numa máquina de 6 núcleos com 530 entradas de inicialização e 270 processos (como administrador):

| | Custo |
|---|---|
| Primeira varredura (sem cache) | ~9 s, 9 s de CPU, 2,3 GB lidos (uma vez) |
| Varreduras seguintes (a cada 30 min) | **~0,2 s**, nenhum arquivo relido |
| Monitor em tempo real (ETW) | **~0,5% de 1 núcleo**, ~40 MB, ~1,2 ms por execução analisada |

Como o custo é mantido baixo:

- **Cache da análise de arquivos**, compartilhado por varreduras, tempo real e remediação, e salvo em disco
  (`filecache.json`), então reiniciar o agente não refaz tudo. Um arquivo só é analisado de novo se mudar o
  tamanho, a data de modificação ou o *ChangeTime* do NTFS (que denuncia um arquivo trocado com a data
  restaurada), e todo arquivo é reverificado a cada 20–28 h.
- **Catálogos do Windows**: a assinatura de cada `.cat` é verificada uma vez, não a cada arquivo coberto por ele.
- **Análise do executável só onde importa**: arquivos sem assinatura válida. Lê só cabeçalhos e seções de código.
- **Prioridade baixa**: a varredura roda numa thread em modo *background* do Windows (CPU, disco e memória com
  prioridade baixa); o monitor em tempo real, em outras threads, não é afetado.
- Leitura com buffer de 1 MB (SHA-256 a ~1,3 GB/s).

O que ainda pesa na primeira varredura: verificação de assinatura (~35%) e busca nos catálogos do Windows (~38%,
principalmente arquivos de terceiros que não estão em nenhum catálogo e obrigam a busca completa).

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
- **Allowlist de ações** no servidor e no agente: só existem `rescan`, `kill_process`, `disable_autorun`, `restore_autorun`, `quarantine_file`, `restore_file`, `block_ip`, `unblock_ip` e `set_protection`. Não há execução de comandos arbitrários.
- **Travas no agente**: confere o caminho do processo antes de finalizar (evita reuso de PID), recusa finalizar processos críticos do Windows, confere o hash do arquivo antes da quarentena e recusa colocar em quarentena arquivos assinados pela Microsoft.
- **Painel**: senha com PBKDF2-SHA256 (600 mil iterações), cookie `HttpOnly`/`Secure`/`SameSite=Strict`, cabeçalho anti-CSRF, bloqueio após 5 tentativas, CSP, e auditoria de cada login e cada comando.

## Limitações conhecidas (próximos passos)

1. **Tempo real para processos e conexões TCP** (inclui a detecção de DDoS). Persistência (registro, tarefas) e arquivos ainda são vistos apenas nas varreduras periódicas; UDP/DNS não são monitorados, então floods de UDP e SYN puro escapam. Próximo passo: ETW de registro, de UDP e de DNS. Sem administrador, processos e conexões muito curtos podem escapar.
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
