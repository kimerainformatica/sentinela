# Compila o painel, roda os testes e gera os executáveis em .\bin
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> Painel web" -ForegroundColor Cyan
Push-Location web
npm ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm ci falhou" }
npm run build
if ($LASTEXITCODE -ne 0) { throw "build do painel falhou" }
Pop-Location

Write-Host "==> Testes" -ForegroundColor Cyan
go test ./...
if ($LASTEXITCODE -ne 0) { throw "testes falharam" }

Write-Host "==> Executáveis" -ForegroundColor Cyan
go build -trimpath -ldflags "-s -w" -o bin/sentinela-server.exe ./cmd/server
if ($LASTEXITCODE -ne 0) { throw "build do servidor falhou" }
go build -trimpath -ldflags "-s -w" -o bin/sentinela-agent.exe ./cmd/agent
if ($LASTEXITCODE -ne 0) { throw "build do agente falhou" }

Write-Host "Pronto: bin\sentinela-server.exe e bin\sentinela-agent.exe" -ForegroundColor Green
