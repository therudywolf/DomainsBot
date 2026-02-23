<#
.SYNOPSIS
    BotTGDomains — unified project manager (Windows / PowerShell)
.DESCRIPTION
    Single entry point for build, launch, export, and maintenance.
    Usage:  .\manage.ps1 <command> [args]
#>
param(
    [Parameter(Position=0)]
    [string]$Command = "help",

    [Parameter(Position=1, ValueFromRemainingArguments)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$EnvFile    = ".env"
$EnvExample = ".env.example"

# ---------- helpers ----------

function Write-Ok    { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[!!]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[ERR] $m" -ForegroundColor Red }
function Write-Step  { param($m) Write-Host "==> $m" -ForegroundColor Cyan }

function Get-ComposeCmd {
    try {
        $null = & docker compose version 2>&1
        return "docker compose"
    } catch {}
    try {
        $null = Get-Command docker-compose -ErrorAction Stop
        return "docker-compose"
    } catch {}
    Write-Err "Docker Compose not found"
    exit 1
}

function Invoke-Compose {
    $dc = Get-ComposeCmd
    $expr = "$dc $($args -join ' ')"
    Invoke-Expression $expr
}

function Test-Docker {
    try {
        $null = Get-Command docker -ErrorAction Stop
    } catch {
        Write-Err "Docker is not installed"
        exit 1
    }
    $null = Get-ComposeCmd
    Write-Ok "Docker & Compose detected"
}

function Ensure-Dirs {
    if (-not (Test-Path "data"))  { New-Item -ItemType Directory -Path "data"  -Force | Out-Null }
    if (-not (Test-Path "wg"))    { New-Item -ItemType Directory -Path "wg"    -Force | Out-Null }
}

function Ensure-Env {
    if (-not (Test-Path $EnvFile)) {
        if (Test-Path $EnvExample) {
            Copy-Item $EnvExample $EnvFile
            Write-Warn ".env created from .env.example -- edit it now!"
            Write-Host "    Required:  TG_TOKEN  and  ADMIN_ID"
            Read-Host  "    Press Enter after editing $EnvFile"
        } else {
            Write-Err ".env.example not found"
            exit 1
        }
    }
}

function Validate-Env {
    $content = Get-Content $EnvFile -Raw
    $token = ($content | Select-String 'TG_TOKEN=(.+)').Matches.Groups[1].Value.Trim()
    $admin = ($content | Select-String 'ADMIN_ID=(.+)').Matches.Groups[1].Value.Trim()

    if (-not $token -or $token -eq "your_telegram_bot_token_here" -or $token -eq "ID") {
        Write-Err "TG_TOKEN is not set in $EnvFile"
        exit 1
    }
    if (-not $admin -or $admin -eq "your_telegram_user_id_here") {
        Write-Err "ADMIN_ID is not set in $EnvFile"
        exit 1
    }
    Write-Ok "Config validated (TG_TOKEN and ADMIN_ID are set)"
}

function Find-DockerImage {
    param([string]$Pattern)
    $images = docker images --format "{{.Repository}}:{{.Tag}}" 2>$null |
        Where-Object { $_ -match $Pattern -and $_ -notmatch '<none>' }
    return ($images | Select-Object -First 1)
}

# ---------- commands ----------

function Cmd-Start {
    Write-Step "Starting BotTGDomains"
    Test-Docker
    Ensure-Dirs
    Ensure-Env
    Validate-Env

    Write-Step "Stopping existing containers (if any)"
    try { Invoke-Compose down 2>$null } catch {}

    Write-Step "Building & starting services"
    Invoke-Compose up -d --build

    Write-Host ""
    Write-Step "Waiting for services to become healthy (10 s)"
    Start-Sleep -Seconds 10

    Write-Host ""
    Invoke-Compose ps
    Write-Host ""
    Write-Ok "Bot is running!  Send /start to the bot in Telegram."
    Write-Host ""
    Write-Host "  Logs:     .\manage.ps1 logs"
    Write-Host "  Stop:     .\manage.ps1 stop"
    Write-Host "  Restart:  .\manage.ps1 restart"
    Write-Host "  Status:   .\manage.ps1 status"
}

function Cmd-Stop {
    Write-Step "Stopping services"
    Test-Docker
    Invoke-Compose down
    Write-Ok "All services stopped"
}

function Cmd-Restart {
    param([string]$Service)
    Test-Docker
    if ($Service) {
        Write-Step "Restarting service: $Service"
        Invoke-Compose restart $Service
    } else {
        Write-Step "Restarting all services"
        try { Invoke-Compose down 2>$null } catch {}
        Invoke-Compose up -d --build
        Start-Sleep -Seconds 5
        Invoke-Compose ps
    }
    Write-Ok "Restart complete"
}

function Cmd-Build {
    param([string]$Flag)
    Write-Step "Building Docker images"
    Test-Docker
    if ($Flag -eq "--no-cache") {
        Invoke-Compose build --no-cache
    } else {
        Invoke-Compose build
    }
    Write-Ok "Build complete"
}

function Cmd-Logs {
    param([string]$Service = "tgscanner")
    Test-Docker
    Invoke-Compose logs -f $Service
}

function Cmd-Status {
    Test-Docker
    Invoke-Compose ps
}

function Cmd-Check {
    Write-Step "Configuration check"
    Test-Docker

    Write-Host ""
    if (Test-Path $EnvFile) {
        Write-Ok ".env file exists"
        Validate-Env
    } else {
        Write-Warn ".env file is missing (run .\manage.ps1 start to create)"
    }

    Write-Host ""
    if (Test-Path "wg\TGBOT.conf") {
        $lines = (Get-Content "wg\TGBOT.conf").Count
        if ($lines -gt 3) {
            Write-Ok "WireGuard config found ($lines lines)"
        } else {
            Write-Warn "WireGuard config looks like a placeholder ($lines lines)"
        }
    } else {
        Write-Warn "WireGuard config not found (wg\TGBOT.conf)"
    }

    Write-Host ""
    if (Test-Path "docker-compose.yml") {
        Write-Ok "docker-compose.yml present"
    } else {
        Write-Err "docker-compose.yml missing!"
    }

    Write-Host ""
    Write-Ok "Check complete"
}

function Cmd-Export {
    Write-Step "Building offline deployment package"
    Test-Docker

    $ts = Get-Date -Format "yyyyMMdd-HHmmss"
    $ExportDir = Join-Path $ProjectRoot "export"
    $ArchiveName = "bottgdomains-offline-$ts"

    Ensure-Dirs
    if (-not (Test-Path "wg\TGBOT.conf")) {
        Set-Content "wg\TGBOT.conf" "# Placeholder -- replace with real config before use"
        Write-Warn "Created placeholder wg\TGBOT.conf"
    }

    Write-Step "Building images (no-cache)"
    Invoke-Compose build --no-cache

    if (Test-Path $ExportDir) { Remove-Item -Recurse -Force $ExportDir }
    New-Item -ItemType Directory -Path "$ExportDir\images"  -Force | Out-Null
    New-Item -ItemType Directory -Path "$ExportDir\project"  -Force | Out-Null

    Write-Step "Exporting Docker images"

    $pname = (Split-Path -Leaf $ProjectRoot).ToLower() -replace '[^a-z0-9]',''
    if ($pname.Length -lt 3) { $pname = "bottgdomains" }

    $gostImg = Find-DockerImage "^${pname}[-_]?gostsslcheck"
    if (-not $gostImg) { $gostImg = Find-DockerImage "gostsslcheck" }
    if (-not $gostImg) { Write-Err "gostsslcheck image not found"; exit 1 }
    Write-Host "  gostsslcheck -> $gostImg"
    docker save $gostImg -o "$ExportDir\images\gostsslcheck.tar"

    $tgImg = Find-DockerImage "^${pname}[-_]?tgscanner"
    if (-not $tgImg) { $tgImg = Find-DockerImage "tgscanner" }
    if (-not $tgImg) { Write-Err "tgscanner image not found"; exit 1 }
    Write-Host "  tgscanner    -> $tgImg"
    docker save $tgImg -o "$ExportDir\images\tgscanner.tar"

    try { docker pull masipcat/wireguard-go:latest 2>$null } catch {}
    $wgExists = docker image inspect masipcat/wireguard-go:latest 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  wireguard    -> masipcat/wireguard-go:latest"
        docker save masipcat/wireguard-go:latest -o "$ExportDir\images\wireguard.tar"
    } else {
        Write-Warn "masipcat/wireguard-go:latest not available locally"
    }

    Write-Step "Copying project files"
    Copy-Item "docker-compose.yml" "$ExportDir\project\"
    if (Test-Path ".env.example") { Copy-Item ".env.example" "$ExportDir\project\" }
    Copy-Item -Recurse "bot" "$ExportDir\project\"
    Copy-Item -Recurse "gost" "$ExportDir\project\"
    if (Test-Path "wg") { Copy-Item -Recurse "wg" "$ExportDir\project\" }
    if (Test-Path "scripts\deploy.sh") { Copy-Item "scripts\deploy.sh" "$ExportDir\project\" }
    if (Test-Path "manage.sh") { Copy-Item "manage.sh" "$ExportDir\project\" }
    foreach ($doc in @("README.md","CHANGELOG.md","DEPLOYMENT_OFFLINE.md","QUICKSTART.md")) {
        if (Test-Path $doc) { Copy-Item $doc "$ExportDir\project\" }
    }

    Get-ChildItem -Path "$ExportDir\project" -Recurse -Directory -Filter "__pycache__" |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ExportDir\project" -Recurse -Filter "*.pyc" |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$ExportDir\project" -Recurse -Directory -Filter ".pytest_cache" |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path "$ExportDir\project\bot\data") {
        Remove-Item -Recurse -Force "$ExportDir\project\bot\data" -ErrorAction SilentlyContinue
    }

    Write-Step "Creating archive"
    $archivePath = Join-Path $ProjectRoot "$ArchiveName.zip"
    Compress-Archive -Path "$ExportDir\images","$ExportDir\project" -DestinationPath $archivePath -Force
    $size = (Get-Item $archivePath).Length / 1MB
    $sizeStr = "{0:N1} MB" -f $size

    $hash = (Get-FileHash $archivePath -Algorithm SHA256).Hash
    Set-Content "$archivePath.sha256" "$hash  $ArchiveName.zip"

    Write-Host ""
    Write-Ok "Offline package ready:"
    Write-Host "  Archive:  $ArchiveName.zip  ($sizeStr)"
    Write-Host "  Checksum: $ArchiveName.zip.sha256"
    Write-Host ""
    Write-Host "  Transfer the archive to the target VM, then:"
    Write-Host "    Expand-Archive $ArchiveName.zip -DestinationPath ."
    Write-Host "    cd project; .\manage.ps1 deploy"
}

function Cmd-Deploy {
    Write-Step "Offline deployment"
    Test-Docker

    $ImagesDir = Join-Path $ProjectRoot "..\images"

    if (Test-Path $ImagesDir) {
        Write-Step "Loading Docker images from $ImagesDir"
        Get-ChildItem "$ImagesDir\*.tar" | ForEach-Object {
            Write-Host "  Loading $($_.Name) ..."
            docker load -i $_.FullName
        }

        $gostImg = Find-DockerImage "gostsslcheck"
        if ($gostImg) {
            foreach ($i in 1..3) {
                docker tag $gostImg "bottgdomains-gostsslcheck${i}:latest" 2>$null
            }
            Write-Ok "Tagged gostsslcheck replicas"
        }

        $tgImg = Find-DockerImage "tgscanner"
        if ($tgImg) { docker tag $tgImg "bottgdomains-tgscanner:latest" 2>$null }

        @"
services:
  gostsslcheck1:
    image: bottgdomains-gostsslcheck1:latest
  gostsslcheck2:
    image: bottgdomains-gostsslcheck2:latest
  gostsslcheck3:
    image: bottgdomains-gostsslcheck3:latest
  tgscanner:
    image: bottgdomains-tgscanner:latest
  wireguard:
    image: masipcat/wireguard-go:latest
"@ | Set-Content "docker-compose.override.yml" -Encoding UTF8

        Write-Ok "docker-compose.override.yml created"
    } else {
        Write-Warn "No images/ directory found -- assuming images already loaded"
    }

    Ensure-Dirs
    Ensure-Env
    Validate-Env

    Write-Step "Starting services (no-build, no-pull)"
    try { Invoke-Compose down 2>$null } catch {}
    Invoke-Compose up -d --no-build --pull never

    Start-Sleep -Seconds 5
    Invoke-Compose ps
    Write-Host ""
    Write-Ok "Deployment complete"
}

function Cmd-Help {
    Write-Host @"

  BotTGDomains Manager
  ====================

  Usage:  .\manage.ps1 <command> [args]

  Commands:
    start              Build & launch all services (quickstart)
    stop               Stop all services
    restart [svc]      Restart all or a specific service
    build [--no-cache] Build Docker images
    logs [svc]         Follow logs (default: tgscanner)
    status             Show service status
    check              Validate configuration
    export             Build offline deployment package
    deploy             Load images & start (offline mode)
    help               Show this message

"@
}

# ---------- dispatch ----------

switch ($Command.ToLower()) {
    "start"   { Cmd-Start }
    "stop"    { Cmd-Stop }
    "restart" { Cmd-Restart -Service ($Args | Select-Object -First 1) }
    "build"   { Cmd-Build -Flag ($Args | Select-Object -First 1) }
    "logs"    { Cmd-Logs -Service ($Args | Select-Object -First 1) }
    "status"  { Cmd-Status }
    "check"   { Cmd-Check }
    "export"  { Cmd-Export }
    "deploy"  { Cmd-Deploy }
    "help"    { Cmd-Help }
    default   { Write-Err "Unknown command: $Command"; Cmd-Help; exit 1 }
}
